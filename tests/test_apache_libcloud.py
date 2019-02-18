from storages.backends.apache_libcloud import LibCloudStorage


def test_init_storage_configures_driver_according_to_extra_params(settings):
    libcloud_providers = {
        'default': {
            'type': 'libcloud.storage.types.Provider.S3_EU_WEST',
            'user': 'AWS_ACCESS_KEY_ID',
            'key': 'AWS_SECRET_ACCESS_KEY',
            'bucket': 'mybucket',
            'host': 'localhost',
            'port': '4572',
            'timeout': 10,
            'secure': False,
        },
    }
    settings.LIBCLOUD_PROVIDERS = libcloud_providers

    storage = LibCloudStorage()

    connection = storage.driver.connection
    provider = libcloud_providers['default']
    assert connection.user_id == provider['user']
    assert connection.timeout == provider['timeout']
    assert connection.key == provider['key']
    assert connection.host == provider['host']
    assert connection.port == provider['port']
    assert connection.secure == int(provider['secure'])
