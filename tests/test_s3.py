import datetime
import gzip
import io
import os
import pickle
import threading
from textwrap import dedent
from unittest import mock
from unittest import skipIf
from urllib.parse import urlparse

import boto3
import boto3.s3.transfer
import botocore
from botocore.config import Config as ClientConfig
from botocore.exceptions import ClientError
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.files.base import ContentFile
from django.core.files.base import File
from django.test import TestCase
from django.test import override_settings
from django.utils.timezone import is_aware
from moto import mock_s3

from storages.backends import s3
from tests.utils import NonSeekableContentFile


class S3ManifestStaticStorageTestStorage(s3.S3ManifestStaticStorage):
    def read_manifest(self):
        return None


class S3StorageTests(TestCase):
    def setUp(self):
        self.storage = s3.S3Storage()
        self.storage._connections.connection = mock.MagicMock()
        self.storage._unsigned_connections.connection = mock.MagicMock()

    @mock.patch("boto3.Session")
    def test_s3_session(self, session):
        with override_settings(AWS_S3_SESSION_PROFILE="test_profile"):
            storage = s3.S3Storage()
            _ = storage.connection
            session.assert_called_once_with(profile_name="test_profile")

    @mock.patch("boto3.Session.resource")
    def test_client_config(self, resource):
        with override_settings(
            AWS_S3_CLIENT_CONFIG=ClientConfig(max_pool_connections=30)
        ):
            storage = s3.S3Storage()
            _ = storage.connection
            resource.assert_called_once()
            self.assertEqual(30, resource.call_args[1]["config"].max_pool_connections)

    @mock.patch("boto3.Session.resource")
    def test_connection_unsiged(self, resource):
        with override_settings(AWS_S3_ADDRESSING_STYLE="virtual"):
            storage = s3.S3Storage()
            _ = storage.unsigned_connection
            resource.assert_called_once()
            self.assertEqual(
                botocore.UNSIGNED, resource.call_args[1]["config"].signature_version
            )
            self.assertEqual(
                "virtual", resource.call_args[1]["config"].s3["addressing_style"]
            )

    def test_pickle_with_bucket(self):
        """
        Test that the storage can be pickled with a bucket attached
        """
        # Ensure the bucket has been used
        self.storage.bucket
        self.assertIsNotNone(self.storage._bucket)

        # Can't pickle MagicMock, but you can't pickle a real Bucket object either
        p = pickle.dumps(self.storage)
        new_storage = pickle.loads(p)

        self.assertIsInstance(new_storage._connections, threading.local)
        # Put the mock connection back in
        new_storage._connections.connection = mock.MagicMock()

        self.assertIsNone(new_storage._bucket)
        new_storage.bucket
        self.assertIsNotNone(new_storage._bucket)

    def test_pickle_without_bucket(self):
        """
        Test that the storage can be pickled, without a bucket instance
        """

        # Can't pickle a threadlocal
        p = pickle.dumps(self.storage)
        new_storage = pickle.loads(p)

        self.assertIsInstance(new_storage._connections, threading.local)

    def test_storage_url_slashes(self):
        """
        Test URL generation.
        """
        self.storage.custom_domain = "example.com"

        # We expect no leading slashes in the path,
        # and trailing slashes should be preserved.
        self.assertEqual(self.storage.url(""), "https://example.com/")
        self.assertEqual(self.storage.url("path"), "https://example.com/path")
        self.assertEqual(self.storage.url("path/"), "https://example.com/path/")
        self.assertEqual(self.storage.url("path/1"), "https://example.com/path/1")
        self.assertEqual(self.storage.url("path/1/"), "https://example.com/path/1/")

    def test_storage_save(self):
        """
        Test saving a file
        """
        name = "test_storage_save.txt"
        content = ContentFile("new content")
        self.storage.save(name, content)
        self.storage.bucket.Object.assert_called_once_with(name)

        obj = self.storage.bucket.Object.return_value
        obj.upload_fileobj.assert_called_with(
            mock.ANY,
            ExtraArgs={
                "ContentType": "text/plain",
            },
            Config=self.storage.transfer_config,
        )

    def test_storage_save_non_seekable(self):
        """
        Test saving a non-seekable file
        """
        name = "test_storage_save.txt"
        content = NonSeekableContentFile("new content")
        self.storage.save(name, content)
        self.storage.bucket.Object.assert_called_once_with(name)

        obj = self.storage.bucket.Object.return_value
        obj.upload_fileobj.assert_called_with(
            mock.ANY,
            ExtraArgs={
                "ContentType": "text/plain",
            },
            Config=self.storage.transfer_config,
        )

    def test_storage_save_with_default_acl(self):
        """
        Test saving a file with user defined ACL.
        """
        name = "test_storage_save.txt"
        content = ContentFile("new content")
        self.storage.default_acl = "private"
        self.storage.save(name, content)
        self.storage.bucket.Object.assert_called_once_with(name)

        obj = self.storage.bucket.Object.return_value
        obj.upload_fileobj.assert_called_with(
            mock.ANY,
            ExtraArgs={
                "ContentType": "text/plain",
                "ACL": "private",
            },
            Config=self.storage.transfer_config,
        )

    def test_storage_object_parameters_not_overwritten_by_default(self):
        """
        Test saving a file with user defined ACL.
        """
        name = "test_storage_save.txt"
        content = ContentFile("new content")
        self.storage.default_acl = "public-read"
        self.storage.object_parameters = {"ACL": "private"}
        self.storage.save(name, content)
        self.storage.bucket.Object.assert_called_once_with(name)

        obj = self.storage.bucket.Object.return_value
        obj.upload_fileobj.assert_called_with(
            mock.ANY,
            ExtraArgs={
                "ContentType": "text/plain",
                "ACL": "private",
            },
            Config=self.storage.transfer_config,
        )

    def test_content_type(self):
        """
        Test saving a file with a None content type.
        """
        name = "test_image.jpg"
        content = ContentFile("data")
        content.content_type = None
        self.storage.save(name, content)
        self.storage.bucket.Object.assert_called_once_with(name)

        obj = self.storage.bucket.Object.return_value
        obj.upload_fileobj.assert_called_with(
            mock.ANY,
            ExtraArgs={
                "ContentType": "image/jpeg",
            },
            Config=self.storage.transfer_config,
        )

    def test_storage_save_gzipped(self):
        """
        Test saving a gzipped file
        """
        name = "test_storage_save.gz"
        content = ContentFile("I am gzip'd")
        self.storage.save(name, content)
        obj = self.storage.bucket.Object.return_value
        obj.upload_fileobj.assert_called_once_with(
            mock.ANY,
            ExtraArgs={
                "ContentType": "application/octet-stream",
                "ContentEncoding": "gzip",
            },
            Config=self.storage.transfer_config,
        )

    def test_content_type_set_explicitly(self):
        name = "test_file.gz"
        content = ContentFile("data")

        def get_object_parameters(name):
            return {"ContentType": "application/gzip"}

        self.storage.get_object_parameters = get_object_parameters
        self.storage.save(name, content)

        obj = self.storage.bucket.Object.return_value
        obj.upload_fileobj.assert_called_with(
            mock.ANY,
            ExtraArgs={
                "ContentType": "application/gzip",
            },
            Config=self.storage.transfer_config,
        )

    def test_storage_save_gzipped_non_seekable(self):
        """
        Test saving a gzipped file
        """
        name = "test_storage_save.gz"
        content = NonSeekableContentFile("I am gzip'd")
        self.storage.save(name, content)
        obj = self.storage.bucket.Object.return_value
        obj.upload_fileobj.assert_called_once_with(
            mock.ANY,
            ExtraArgs={
                "ContentType": "application/octet-stream",
                "ContentEncoding": "gzip",
            },
            Config=self.storage.transfer_config,
        )

    def test_storage_save_gzip(self):
        """
        Test saving a file with gzip enabled.
        """
        self.storage.gzip = True
        name = "test_storage_save.css"
        content = ContentFile("I should be gzip'd")
        self.storage.save(name, content)
        obj = self.storage.bucket.Object.return_value
        obj.upload_fileobj.assert_called_with(
            mock.ANY,
            ExtraArgs={
                "ContentType": "text/css",
                "ContentEncoding": "gzip",
            },
            Config=self.storage.transfer_config,
        )
        args, kwargs = obj.upload_fileobj.call_args
        content = args[0]
        zfile = gzip.GzipFile(mode="rb", fileobj=content)
        self.assertEqual(zfile.read(), b"I should be gzip'd")

    def test_storage_save_gzip_twice(self):
        """
        Test saving the same file content twice with gzip enabled.
        """
        # Given
        self.storage.gzip = True
        name = "test_storage_save.css"
        content = ContentFile("I should be gzip'd")

        # When
        self.storage.save(name, content)
        self.storage.save("test_storage_save_2.css", content)

        # Then
        obj = self.storage.bucket.Object.return_value
        obj.upload_fileobj.assert_called_with(
            mock.ANY,
            ExtraArgs={
                "ContentType": "text/css",
                "ContentEncoding": "gzip",
            },
            Config=self.storage.transfer_config,
        )
        args, kwargs = obj.upload_fileobj.call_args
        content = args[0]
        zfile = gzip.GzipFile(mode="rb", fileobj=content)
        self.assertEqual(zfile.read(), b"I should be gzip'd")

    def test_compress_content_len(self):
        """
        Test that file returned by _compress_content() is readable.
        """
        self.storage.gzip = True
        content = ContentFile(b"I should be gzip'd")
        content = self.storage._compress_content(content)
        self.assertTrue(len(content.read()) > 0)

    def test_storage_open_read_string(self):
        """
        Test opening a file in "r" mode (ie reading as string, not bytes)
        """
        name = "test_open_read_string.txt"
        with self.storage.open(name, "r") as file:
            content_str = file.read()
            self.assertEqual(content_str, "")

    def test_storage_open_write(self):
        """
        Test opening a file in write mode
        """
        name = "test_open_for_writïng.txt"
        content = "new content"

        # Set the encryption flag used for multipart uploads
        self.storage.object_parameters = {
            "ServerSideEncryption": "AES256",
            "StorageClass": "REDUCED_REDUNDANCY",
            "ACL": "public-read",
        }

        with self.storage.open(name, "wb") as file:
            self.storage.bucket.Object.assert_called_with(name)
            obj = self.storage.bucket.Object.return_value
            # Set the name of the mock object
            obj.key = name

            multipart = obj.initiate_multipart_upload.return_value
            multipart.Part.return_value.upload.side_effect = [
                {"ETag": "123"},
            ]
            file.write(content)
            obj.initiate_multipart_upload.assert_called_with(
                ACL="public-read",
                ContentType="text/plain",
                ServerSideEncryption="AES256",
                StorageClass="REDUCED_REDUNDANCY",
            )

        multipart.Part.assert_called_with(1)
        part = multipart.Part.return_value
        part.upload.assert_called_with(Body=content.encode())
        multipart.complete.assert_called_once_with(
            MultipartUpload={"Parts": [{"ETag": "123", "PartNumber": 1}]}
        )

    def test_write_bytearray(self):
        """Test that bytearray write exactly (no extra "bytearray" from stringify)."""
        name = "saved_file.bin"
        content = bytearray(b"content")
        with self.storage.open(name, "wb") as file:
            obj = self.storage.bucket.Object.return_value
            # Set the name of the mock object
            obj.key = name
            bytes_written = file.write(content)
            self.assertEqual(len(content), bytes_written)

    def test_storage_open_no_write(self):
        """
        Test opening file in write mode and closing without writing.

        A file should be created as by obj.put(...).
        """
        name = "test_open_no_write.txt"

        # Set the encryption flag used for puts
        self.storage.object_parameters = {
            "ServerSideEncryption": "AES256",
            "StorageClass": "REDUCED_REDUNDANCY",
        }

        with self.storage.open(name, "wb"):
            self.storage.bucket.Object.assert_called_with(name)
            obj = self.storage.bucket.Object.return_value
            obj.load.side_effect = ClientError(
                {"Error": {}, "ResponseMetadata": {"HTTPStatusCode": 404}},
                "head_bucket",
            )

            # Set the name of the mock object
            obj.key = name

        obj.load.assert_called_once_with()
        obj.put.assert_called_once_with(
            Body=b"",
            ContentType="text/plain",
            ServerSideEncryption="AES256",
            StorageClass="REDUCED_REDUNDANCY",
        )

    def test_storage_open_no_overwrite_existing(self):
        """
        Test opening an existing file in write mode and closing without writing.
        """
        name = "test_open_no_overwrite_existing.txt"

        # Set the encryption flag used for puts
        self.storage.object_parameters = {
            "ServerSideEncryption": "AES256",
            "StorageClass": "REDUCED_REDUNDANCY",
        }

        with self.storage.open(name, "wb"):
            self.storage.bucket.Object.assert_called_with(name)
            obj = self.storage.bucket.Object.return_value

            # Set the name of the mock object
            obj.key = name

        obj.load.assert_called_once_with()
        obj.put.assert_not_called()

    def test_storage_write_beyond_buffer_size(self):
        """
        Test writing content that exceeds the buffer size
        """
        name = "test_open_for_writïng_beyond_buffer_size.txt"

        # Set the encryption flag used for multipart uploads
        self.storage.object_parameters = {
            "ServerSideEncryption": "AES256",
            "StorageClass": "REDUCED_REDUNDANCY",
        }

        with self.storage.open(name, "wb") as file:
            self.storage.bucket.Object.assert_called_with(name)
            obj = self.storage.bucket.Object.return_value
            # Set the name of the mock object
            obj.key = name

            # Initiate the multipart upload
            file.write("")
            obj.initiate_multipart_upload.assert_called_with(
                ContentType="text/plain",
                ServerSideEncryption="AES256",
                StorageClass="REDUCED_REDUNDANCY",
            )
            multipart = obj.initiate_multipart_upload.return_value

            # Write content at least twice as long as the buffer size
            written_content = ""
            counter = 1
            multipart.Part.return_value.upload.side_effect = [
                {"ETag": "123"},
                {"ETag": "456"},
            ]
            while len(written_content) < 2 * file.buffer_size:
                content = "hello, aws {counter}\n".format(counter=counter)
                # Write more than just a few bytes in each iteration to keep the
                # test reasonably fast
                content += "*" * int(file.buffer_size / 10)
                file.write(content)
                written_content += content
                counter += 1

        self.assertListEqual(
            multipart.Part.call_args_list, [mock.call(1), mock.call(2)]
        )
        part = multipart.Part.return_value
        uploaded_content = "".join(
            args_list[1]["Body"].decode() for args_list in part.upload.call_args_list
        )
        self.assertEqual(uploaded_content, written_content)
        multipart.complete.assert_called_once_with(
            MultipartUpload={
                "Parts": [
                    {"ETag": "123", "PartNumber": 1},
                    {"ETag": "456", "PartNumber": 2},
                ]
            }
        )

    def test_storage_exists(self):
        self.assertTrue(self.storage.exists("file.txt"))
        self.storage.connection.meta.client.head_object.assert_called_with(
            Bucket=self.storage.bucket_name,
            Key="file.txt",
        )

    def test_storage_exists_ssec(self):
        params = {"SSECustomerKey": "xyz", "CacheControl": "never"}
        self.storage.get_object_parameters = lambda name: params
        self.storage.file_overwrite = False
        self.assertTrue(self.storage.exists("file.txt"))
        self.storage.connection.meta.client.head_object.assert_called_with(
            Bucket=self.storage.bucket_name, Key="file.txt", SSECustomerKey="xyz"
        )

    def test_storage_exists_false(self):
        self.storage.connection.meta.client.head_object.side_effect = ClientError(
            {"Error": {}, "ResponseMetadata": {"HTTPStatusCode": 404}},
            "HeadObject",
        )
        self.assertFalse(self.storage.exists("file.txt"))
        self.storage.connection.meta.client.head_object.assert_called_with(
            Bucket=self.storage.bucket_name,
            Key="file.txt",
        )

    def test_storage_exists_other_error_reraise(self):
        self.storage.connection.meta.client.head_object.side_effect = ClientError(
            {"Error": {}, "ResponseMetadata": {"HTTPStatusCode": 403}},
            "HeadObject",
        )
        with self.assertRaises(ClientError) as cm:
            self.storage.exists("file.txt")

        self.assertEqual(
            cm.exception.response["ResponseMetadata"]["HTTPStatusCode"], 403
        )

    def test_storage_delete(self):
        self.storage.delete("path/to/file.txt")
        self.storage.bucket.Object.assert_called_with("path/to/file.txt")
        self.storage.bucket.Object.return_value.delete.assert_called_with()

    def test_storage_delete_does_not_exist(self):
        self.storage.bucket.Object("file.txt").delete.side_effect = ClientError(
            {"Error": {}, "ResponseMetadata": {"HTTPStatusCode": 404}},
            "DeleteObject",
        )
        self.storage.delete("file.txt")
        # No problem

    def test_storage_delete_other_error_reraise(self):
        self.storage.bucket.Object("file.txt").delete.side_effect = ClientError(
            {"Error": {}, "ResponseMetadata": {"HTTPStatusCode": 403}},
            "DeleteObject",
        )
        with self.assertRaises(ClientError) as cm:
            self.storage.delete("file.txt")

        self.assertEqual(
            cm.exception.response["ResponseMetadata"]["HTTPStatusCode"], 403
        )

    def test_storage_listdir_base(self):
        # Files:
        #   some/path/1.txt
        #   2.txt
        #   other/path/3.txt
        #   4.txt
        pages = [
            {
                "CommonPrefixes": [
                    {"Prefix": "some"},
                    {"Prefix": "other"},
                ],
                "Contents": [
                    {"Key": "2.txt"},
                    {"Key": "4.txt"},
                ],
            },
        ]

        paginator = mock.MagicMock()
        paginator.paginate.return_value = pages
        self.storage._connections.connection.meta.client.get_paginator.return_value = (
            paginator
        )

        dirs, files = self.storage.listdir("")
        paginator.paginate.assert_called_with(
            Bucket=settings.AWS_STORAGE_BUCKET_NAME, Delimiter="/", Prefix=""
        )

        self.assertEqual(dirs, ["some", "other"])
        self.assertEqual(files, ["2.txt", "4.txt"])

    def test_storage_listdir_subdir(self):
        # Files:
        #   some/path/1.txt
        #   some/2.txt
        pages = [
            {
                "CommonPrefixes": [
                    {"Prefix": "some/path"},
                ],
                "Contents": [
                    {"Key": "some/2.txt"},
                ],
            },
        ]

        paginator = mock.MagicMock()
        paginator.paginate.return_value = pages
        self.storage._connections.connection.meta.client.get_paginator.return_value = (
            paginator
        )

        dirs, files = self.storage.listdir("some/")
        paginator.paginate.assert_called_with(
            Bucket=settings.AWS_STORAGE_BUCKET_NAME, Delimiter="/", Prefix="some/"
        )

        self.assertEqual(dirs, ["path"])
        self.assertEqual(files, ["2.txt"])

    def test_storage_listdir_empty(self):
        # Files:
        #   dir/
        pages = [
            {
                "Contents": [
                    {"Key": "dir/"},
                ],
            },
        ]

        paginator = mock.MagicMock()
        paginator.paginate.return_value = pages
        self.storage._connections.connection.meta.client.get_paginator.return_value = (
            paginator
        )

        dirs, files = self.storage.listdir("dir/")
        paginator.paginate.assert_called_with(
            Bucket=settings.AWS_STORAGE_BUCKET_NAME, Delimiter="/", Prefix="dir/"
        )

        self.assertEqual(dirs, [])
        self.assertEqual(files, [])

    def test_storage_size(self):
        obj = self.storage.bucket.Object.return_value
        obj.content_length = 4098

        name = "file.txt"
        self.assertEqual(self.storage.size(name), obj.content_length)

    def test_storage_size_not_exists(self):
        self.storage.bucket.Object.side_effect = ClientError(
            {"Error": {}, "ResponseMetadata": {"HTTPStatusCode": 404}},
            "HeadObject",
        )
        name = "file.txt"
        with self.assertRaisesMessage(
            FileNotFoundError, "File does not exist: file.txt"
        ):
            self.storage.size(name)

    def test_storage_mtime(self):
        # Test both USE_TZ cases
        for use_tz in (True, False):
            with self.settings(USE_TZ=use_tz):
                self._test_storage_mtime(use_tz)

    def _test_storage_mtime(self, use_tz):
        obj = self.storage.bucket.Object.return_value
        obj.last_modified = datetime.datetime.now(datetime.timezone.utc)

        name = "file.txt"
        self.assertIs(
            settings.USE_TZ,
            is_aware(self.storage.get_modified_time(name)),
            (
                "{} datetime object expected from get_modified_time() when USE_TZ={}"
            ).format(("Naive", "Aware")[settings.USE_TZ], settings.USE_TZ),
        )

    def test_storage_url(self):
        name = "test_storage_size.txt"
        url = "http://aws.amazon.com/%s" % name
        self.storage.connection.meta.client.generate_presigned_url.return_value = url
        self.storage.bucket.name = "bucket"
        self.assertEqual(self.storage.url(name), url)
        self.storage.connection.meta.client.generate_presigned_url.assert_called_with(
            "get_object",
            Params={"Bucket": self.storage.bucket.name, "Key": name},
            ExpiresIn=self.storage.querystring_expire,
            HttpMethod=None,
        )

        custom_expire = 123
        self.assertEqual(self.storage.url(name, expire=custom_expire), url)
        self.storage.connection.meta.client.generate_presigned_url.assert_called_with(
            "get_object",
            Params={"Bucket": self.storage.bucket.name, "Key": name},
            ExpiresIn=custom_expire,
            HttpMethod=None,
        )

        custom_method = "HEAD"
        self.assertEqual(self.storage.url(name, http_method=custom_method), url)
        self.storage.connection.meta.client.generate_presigned_url.assert_called_with(
            "get_object",
            Params={"Bucket": self.storage.bucket.name, "Key": name},
            ExpiresIn=self.storage.querystring_expire,
            HttpMethod=custom_method,
        )

    def test_url_unsigned(self):
        self.storage.querystring_auth = False
        self.storage.url("test_name")
        self.storage.unsigned_connection.meta.client.generate_presigned_url.assert_called_once()

    @mock.patch("storages.backends.s3.datetime")
    def test_storage_url_custom_domain_signed_urls(self, dt):
        key_id = "test-key"
        filename = "file.txt"
        pem = dedent(
            """\
            -----BEGIN RSA PRIVATE KEY-----
            MIICWwIBAAKBgQCXVuwcMk+JmVSKuQ1K4dZx4Z1dEcRQgTlqvhAyljIpttXlZh2/
            fD3GkJCiqfwEmo+cdNK/LFzRj/CX8Wz1z1lH2USONpG6sAkotkatCbejiItDu5y6
            janGJHfuWXu6B/o9gwZylU1gIsePY3lLNk+r9QhXUO4jXw6zLJftVwKPhQIDAQAB
            AoGAbpkRV9HUmoQ5al+uPSkp5HOy4s8XHpYxdbaMc8ubwSxiyJCF8OhE5RXE/Xso
            N90UUox1b0xmUKfWddPzgvgTD/Ub7D6Ukf+nVWDX60tWgNxICAUHptGL3tWweaAy
            H+0+vZ0TzvTt9r00vW0FzO7F8X9/Rs1ntDRLtF3RCCxdq0kCQQDHFu+t811lCvy/
            67rMEKGvNsNNSTrzOrNr3PqUrCnOrzKazjFVjsKv5VzI/U+rXGYKWJsMpuCFiHZ3
            DILUC09TAkEAwpm2S6MN6pzn9eY6pmhOxZ+GQGGRUkKZfC1GDxaRSRb8sKTjptYw
            WSemJSxiDzdj3Po2hF0lbhkpJgUq6xnCxwJAZgHHfn5CLSJrDD7Q7/vZi/foK3JJ
            BRTfl3Wa4pAvv5meuRjKyEakVBGV79lyd5+ZHNX3Y40hXunjoO3FHrZIxwJAdRzu
            waxahrRxQOKSr20c4wAzWnGddIUSO9I/VHs/al5EKsbBHrnOlQkwizSfuwqZtfZ7
            csNf8FeCFRiNELoLJwJAZxWBE2+8J9VW9AQ0SE7j4FyM/B8FvRhF5PLAAsw/OxHO
            SxiFP7Ptdac1tm5H5zOqaqSHWphI19HNNilXKmxuCA==
            -----END RSA PRIVATE KEY-----"""
        ).encode("ascii")

        url = "https://mock.cloudfront.net/file.txt"
        signed_url = (
            url
            + "?Expires=3600&Signature=DbqVgh3FHtttQxof214tSAVE8Nqn3Q4Ii7eR3iykbOqAPbV"
            "89HC3EB~0CWxarpLNtbfosS5LxiP5EutriM7E8uR4Gm~UVY-PFUjPcwqdnmAiKJF0EVs7koJc"
            "MR8MKDStuWfFKVUPJ8H7ORYTOrixyHBV2NOrpI6SN5UX6ctNM50_&Key-Pair-Id=test-key"
        )

        self.storage.custom_domain = "mock.cloudfront.net"

        for pem_to_signer in (s3._use_cryptography_signer(), s3._use_rsa_signer()):
            self.storage.cloudfront_signer = pem_to_signer(key_id, pem)
            self.storage.querystring_auth = False
            self.assertEqual(self.storage.url(filename), url)

            self.storage.querystring_auth = True
            dt.utcnow.return_value = datetime.datetime.utcfromtimestamp(0)
            self.assertEqual(self.storage.url(filename), signed_url)

    def test_generated_url_is_encoded(self):
        self.storage.custom_domain = "mock.cloudfront.net"
        filename = "whacky & filename.mp4"
        url = self.storage.url(filename)
        parsed_url = urlparse(url)
        self.assertEqual(parsed_url.path, "/whacky%20%26%20filename.mp4")
        self.assertFalse(self.storage.bucket.meta.client.generate_presigned_url.called)

    def test_special_characters(self):
        self.storage.custom_domain = "mock.cloudfront.net"

        name = "ãlöhâ.jpg"
        content = ContentFile("new content")
        self.storage.save(name, content)
        self.storage.bucket.Object.assert_called_once_with(name)

        url = self.storage.url(name)
        parsed_url = urlparse(url)
        self.assertEqual(parsed_url.path, "/%C3%A3l%C3%B6h%C3%A2.jpg")

    def test_custom_domain_parameters(self):
        self.storage.custom_domain = "mock.cloudfront.net"
        filename = "filename.mp4"
        url = self.storage.url(filename, parameters={"version": 10})
        parsed_url = urlparse(url)
        self.assertEqual(parsed_url.path, "/filename.mp4")
        self.assertEqual(parsed_url.query, "version=10")

    @skipIf(threading is None, "Test requires threading")
    def test_connection_threading(self):
        connections = []

        def thread_storage_connection():
            connections.append(self.storage.connection)

        for _ in range(2):
            t = threading.Thread(target=thread_storage_connection)
            t.start()
            t.join()

        # Connection for each thread needs to be unique
        self.assertIsNot(connections[0], connections[1])

    def test_location_leading_slash(self):
        msg = (
            "S3Storage.location cannot begin with a leading slash. "
            "Found '/'. Use '' instead."
        )
        with self.assertRaises(ImproperlyConfigured, msg=msg):
            s3.S3Storage(location="/")

    def test_override_settings(self):
        with override_settings(AWS_LOCATION="foo1"):
            storage = s3.S3Storage()
            self.assertEqual(storage.location, "foo1")
        with override_settings(AWS_LOCATION="foo2"):
            storage = s3.S3Storage()
            self.assertEqual(storage.location, "foo2")

    def test_override_class_variable(self):
        class MyStorage1(s3.S3Storage):
            location = "foo1"

        storage = MyStorage1()
        self.assertEqual(storage.location, "foo1")

        class MyStorage2(s3.S3Storage):
            location = "foo2"

        storage = MyStorage2()
        self.assertEqual(storage.location, "foo2")

    def test_override_init_argument(self):
        storage = s3.S3Storage(location="foo1")
        self.assertEqual(storage.location, "foo1")
        storage = s3.S3Storage(location="foo2")
        self.assertEqual(storage.location, "foo2")

    def test_use_threads_false(self):
        with override_settings(AWS_S3_USE_THREADS=False):
            storage = s3.S3Storage()
            self.assertFalse(storage.transfer_config.use_threads)

    def test_transfer_config(self):
        storage = s3.S3Storage()
        self.assertTrue(storage.transfer_config.use_threads)

        transfer_config = boto3.s3.transfer.TransferConfig(use_threads=False)
        with override_settings(AWS_S3_TRANSFER_CONFIG=transfer_config):
            storage = s3.S3Storage()
            self.assertFalse(storage.transfer_config.use_threads)

    def test_cloudfront_config(self):
        # Valid configs
        storage = s3.S3Storage()
        self.assertIsNone(storage.cloudfront_signer)

        key_id = "test-id"
        pem = dedent(
            """\
            -----BEGIN RSA PRIVATE KEY-----
            MIICWwIBAAKBgQCXVuwcMk+JmVSKuQ1K4dZx4Z1dEcRQgTlqvhAyljIpttXlZh2/
            fD3GkJCiqfwEmo+cdNK/LFzRj/CX8Wz1z1lH2USONpG6sAkotkatCbejiItDu5y6
            janGJHfuWXu6B/o9gwZylU1gIsePY3lLNk+r9QhXUO4jXw6zLJftVwKPhQIDAQAB
            AoGAbpkRV9HUmoQ5al+uPSkp5HOy4s8XHpYxdbaMc8ubwSxiyJCF8OhE5RXE/Xso
            N90UUox1b0xmUKfWddPzgvgTD/Ub7D6Ukf+nVWDX60tWgNxICAUHptGL3tWweaAy
            H+0+vZ0TzvTt9r00vW0FzO7F8X9/Rs1ntDRLtF3RCCxdq0kCQQDHFu+t811lCvy/
            67rMEKGvNsNNSTrzOrNr3PqUrCnOrzKazjFVjsKv5VzI/U+rXGYKWJsMpuCFiHZ3
            DILUC09TAkEAwpm2S6MN6pzn9eY6pmhOxZ+GQGGRUkKZfC1GDxaRSRb8sKTjptYw
            WSemJSxiDzdj3Po2hF0lbhkpJgUq6xnCxwJAZgHHfn5CLSJrDD7Q7/vZi/foK3JJ
            BRTfl3Wa4pAvv5meuRjKyEakVBGV79lyd5+ZHNX3Y40hXunjoO3FHrZIxwJAdRzu
            waxahrRxQOKSr20c4wAzWnGddIUSO9I/VHs/al5EKsbBHrnOlQkwizSfuwqZtfZ7
            csNf8FeCFRiNELoLJwJAZxWBE2+8J9VW9AQ0SE7j4FyM/B8FvRhF5PLAAsw/OxHO
            SxiFP7Ptdac1tm5H5zOqaqSHWphI19HNNilXKmxuCA==
            -----END RSA PRIVATE KEY-----"""
        ).encode("ascii")

        with override_settings(AWS_CLOUDFRONT_KEY_ID=key_id, AWS_CLOUDFRONT_KEY=pem):
            storage = s3.S3Storage()
            self.assertIsNotNone(storage.cloudfront_signer)

            # allow disabling cloudfront signing
            storage = s3.S3Storage(cloudfront_signer=None)
            self.assertIsNone(storage.cloudfront_signer)

            # allow disabling cloudfront signing in subclass
            class Storage(s3.S3Storage):
                cloudfront_signer = None

            self.assertIsNone(Storage().cloudfront_signer)

        storage = s3.S3Storage(cloudfront_key_id=key_id, cloudfront_key=pem)
        self.assertIsNotNone(storage.cloudfront_signer)

        cloudfront_signer = storage.get_cloudfront_signer(key_id, pem)
        storage = s3.S3Storage(cloudfront_signer=cloudfront_signer)
        self.assertIsNotNone(storage.cloudfront_signer)

        with override_settings(AWS_CLOUDFRONT_KEY_ID=key_id):
            storage = s3.S3Storage(cloudfront_key=pem)
            self.assertIsNotNone(storage.cloudfront_signer)

        # Invalid configs
        msg = (
            "Both AWS_CLOUDFRONT_KEY_ID/cloudfront_key_id and "
            "AWS_CLOUDFRONT_KEY/cloudfront_key must be provided together."
        )
        with override_settings(AWS_CLOUDFRONT_KEY_ID=key_id):
            with self.assertRaisesMessage(ImproperlyConfigured, msg):
                storage = s3.S3Storage()

        with override_settings(AWS_CLOUDFRONT_KEY=pem):
            with self.assertRaisesMessage(ImproperlyConfigured, msg):
                storage = s3.S3Storage()

        with self.assertRaisesMessage(ImproperlyConfigured, msg):
            storage = s3.S3Storage(cloudfront_key_id=key_id)

        with self.assertRaisesMessage(ImproperlyConfigured, msg):
            storage = s3.S3Storage(cloudfront_key=pem)

    def test_auth_config(self):
        # Valid configs
        with override_settings(
            AWS_S3_ACCESS_KEY_ID="foo", AWS_S3_SECRET_ACCESS_KEY="boo"
        ):
            storage = s3.S3Storage()
            self.assertEqual(storage.access_key, "foo")
            self.assertEqual(storage.secret_key, "boo")

        with override_settings(AWS_ACCESS_KEY_ID="foo", AWS_SECRET_ACCESS_KEY="boo"):
            storage = s3.S3Storage()
            self.assertEqual(storage.access_key, "foo")
            self.assertEqual(storage.secret_key, "boo")

        with mock.patch.dict(
            os.environ,
            {"AWS_S3_ACCESS_KEY_ID": "foo", "AWS_S3_SECRET_ACCESS_KEY": "boo"},
        ):
            storage = s3.S3Storage()
            self.assertEqual(storage.access_key, "foo")
            self.assertEqual(storage.secret_key, "boo")

        with mock.patch.dict(
            os.environ, {"AWS_ACCESS_KEY_ID": "foo", "AWS_SECRET_ACCESS_KEY": "boo"}
        ):
            storage = s3.S3Storage()
            self.assertEqual(storage.access_key, "foo")
            self.assertEqual(storage.secret_key, "boo")

        storage = s3.S3Storage(access_key="foo", secret_key="boo")
        self.assertEqual(storage.access_key, "foo")
        self.assertEqual(storage.secret_key, "boo")

        # Invalid configs
        msg = (
            "AWS_S3_SESSION_PROFILE/session_profile should not be provided with "
            "AWS_S3_ACCESS_KEY_ID/access_key and AWS_S3_SECRET_ACCESS_KEY/secret_key"
        )
        with override_settings(
            AWS_ACCESS_KEY_ID="foo",
            AWS_SECRET_ACCESS_KEY="boo",
            AWS_S3_SESSION_PROFILE="moo",
        ):
            with self.assertRaisesMessage(ImproperlyConfigured, msg):
                storage = s3.S3Storage()

        with self.assertRaisesMessage(ImproperlyConfigured, msg):
            storage = s3.S3Storage(
                access_key="foo", secret_key="boo", session_profile="moo"
            )

    def test_security_token(self):
        with override_settings(AWS_SESSION_TOKEN="baz"):
            storage = s3.S3Storage()
            self.assertEqual(storage.security_token, "baz")

        with override_settings(AWS_SECURITY_TOKEN="baz"):
            storage = s3.S3Storage()
            self.assertEqual(storage.security_token, "baz")

        with mock.patch.dict(
            os.environ,
            {"AWS_SESSION_TOKEN": "baz"},
        ):
            storage = s3.S3Storage()
            self.assertEqual(storage.security_token, "baz")

        with mock.patch.dict(
            os.environ,
            {"AWS_SECURITY_TOKEN": "baz"},
        ):
            storage = s3.S3Storage()
            self.assertEqual(storage.security_token, "baz")


class S3StaticStorageTests(TestCase):
    def setUp(self):
        self.storage = s3.S3StaticStorage()
        self.storage._connections.connection = mock.MagicMock()

    def test_querystring_auth(self):
        self.assertFalse(self.storage.querystring_auth)


class S3ManifestStaticStorageTests(TestCase):
    def setUp(self):
        self.storage = S3ManifestStaticStorageTestStorage()
        self.storage._connections.connection = mock.MagicMock()

    def test_querystring_auth(self):
        self.assertFalse(self.storage.querystring_auth)

    def test_save(self):
        self.storage.save("x.txt", ContentFile(b"abc"))


class S3FileTests(TestCase):
    # Remove the override_settings after Python3.7 is dropped
    @override_settings(AWS_S3_OBJECT_PARAMETERS={"ContentType": "text/html"})
    def setUp(self) -> None:
        self.storage = s3.S3Storage()
        self.storage._connections.connection = mock.MagicMock()

    def test_loading_ssec(self):
        params = {"SSECustomerKey": "xyz", "CacheControl": "never"}
        self.storage.get_object_parameters = lambda name: params

        filtered = {"SSECustomerKey": "xyz"}
        f = s3.S3File("test", "r", self.storage)
        f.obj.load.assert_called_once_with(**filtered)

        f.file
        f.obj.download_fileobj.assert_called_once_with(
            mock.ANY, ExtraArgs=filtered, Config=self.storage.transfer_config
        )

    def test_closed(self):
        with s3.S3File("test", "wb", self.storage) as f:
            with self.subTest("after init"):
                self.assertFalse(f.closed)

            with self.subTest("after file access"):
                # Ensure _get_file has been called
                f.file
                self.assertFalse(f.closed)

            with self.subTest("after close"):
                f.close()
                self.assertTrue(f.closed)

            with self.subTest("reopening"):
                f.file
                self.assertFalse(f.closed)

    def test_reopening(self):
        f = s3.S3File("test", "wb", self.storage)

        with f.open() as fp:
            fp.write(b"xyz")

        with f.open() as fp:
            fp.write(b"xyz")

        # Properties are reset
        self.assertEqual(f._write_counter, 0)
        self.assertEqual(f._raw_bytes_written, 0)
        self.assertFalse(f._is_dirty)
        self.assertIsNone(f._multipart)


@mock_s3
class S3StorageTestsWithMoto(TestCase):
    """
    Using mock_s3 as a class decorator automatically decorates methods,
    but NOT classmethods or staticmethods.
    """

    def setUp(cls):
        super().setUp()

        cls.storage = s3.S3Storage()
        cls.bucket = cls.storage.connection.Bucket(settings.AWS_STORAGE_BUCKET_NAME)
        cls.bucket.create()

    def test_save_bytes_file(self):
        self.storage.save("bytes_file.txt", File(io.BytesIO(b"foo1")))

        self.assertEqual(
            b"foo1",
            self.bucket.Object("bytes_file.txt").get()["Body"].read(),
        )

    def test_save_string_file(self):
        self.storage.save("string_file.txt", File(io.StringIO("foo2")))

        self.assertEqual(
            b"foo2",
            self.bucket.Object("string_file.txt").get()["Body"].read(),
        )

    def test_save_bytes_content_file(self):
        self.storage.save("bytes_content.txt", ContentFile(b"foo3"))

        self.assertEqual(
            b"foo3",
            self.bucket.Object("bytes_content.txt").get()["Body"].read(),
        )

    def test_save_string_content_file(self):
        self.storage.save("string_content.txt", ContentFile("foo4"))

        self.assertEqual(
            b"foo4",
            self.bucket.Object("string_content.txt").get()["Body"].read(),
        )

    def test_content_type_guess(self):
        """
        Test saving a file where the ContentType is guessed from the filename.
        """
        name = "test_image.jpg"
        content = ContentFile(b"data")
        content.content_type = None
        self.storage.save(name, content)

        s3_object_fetched = self.bucket.Object(name).get()
        self.assertEqual(b"data", s3_object_fetched["Body"].read())
        self.assertEqual(s3_object_fetched["ContentType"], "image/jpeg")

    def test_content_type_attribute(self):
        """
        Test saving a file with a custom content type attribute.
        """
        content = ContentFile(b"data")
        content.content_type = "test/foo"
        self.storage.save("test_file", content)

        s3_object_fetched = self.bucket.Object("test_file").get()
        self.assertEqual(b"data", s3_object_fetched["Body"].read())
        self.assertEqual(s3_object_fetched["ContentType"], "test/foo")

    def test_content_type_not_detectable(self):
        """
        Test saving a file with no detectable content type.
        """
        content = ContentFile(b"data")
        content.content_type = None
        self.storage.save("test_file", content)

        s3_object_fetched = self.bucket.Object("test_file").get()
        self.assertEqual(b"data", s3_object_fetched["Body"].read())
        self.assertEqual(
            s3_object_fetched["ContentType"],
            s3.S3Storage.default_content_type,
        )

    def test_storage_open_reading_with_newlines(self):
        """Test file reading with "r" and "rb" and various newline characters."""
        name = "test_storage_open_read_with_newlines.txt"
        with io.BytesIO() as temp_file:
            temp_file.write(b"line1\nline2\r\nmore\rtext\n")
            self.storage.save(name, temp_file)
            file = self.storage.open(name, "r")
            content_str = file.read()
            file.close()
        self.assertEqual(content_str, "line1\nline2\nmore\ntext\n")

        with io.BytesIO() as temp_file:
            temp_file.write(b"line1\nline2\r\nmore\rtext\n")
            self.storage.save(name, temp_file)
            file = self.storage.open(name, "rb")
            content_str = file.read()
            file.close()
        self.assertEqual(content_str, b"line1\nline2\r\nmore\rtext\n")

        with io.BytesIO() as temp_file:
            temp_file.write(b"line1\nline2\r\nmore\rtext")
            self.storage.save(name, temp_file)
            file = self.storage.open(name, "r")
            content_lines = file.readlines()
            file.close()
        self.assertEqual(content_lines, ["line1\n", "line2\n", "more\n", "text"])

        with io.BytesIO() as temp_file:
            temp_file.write(b"line1\nline2\r\nmore\rtext")
            self.storage.save(name, temp_file)
            file = self.storage.open(name, "rb")
            content_lines = file.readlines()
            file.close()
        self.assertEqual(content_lines, [b"line1\n", b"line2\r\n", b"more\r", b"text"])


class TestBackwardsNames(TestCase):
    def test_importing(self):
        from storages.backends.s3boto3 import S3Boto3Storage  # noqa
        from storages.backends.s3boto3 import S3Boto3StorageFile  # noqa
        from storages.backends.s3boto3 import S3ManifestStaticStorage  # noqa
        from storages.backends.s3boto3 import S3StaticStorage  # noqa
