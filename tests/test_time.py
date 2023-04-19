from datetime import datetime
from datetime import timedelta
from datetime import timezone
from datetime import tzinfo
from enum import Enum
from typing import Iterable
from typing import Optional
from typing import Sequence
from typing import Type

from django.core.files.storage import Storage
from django.test import TestCase
from django.utils.timezone import get_current_timezone

from storages.time import TimeStorageMixin
from storages.utils import setting

UTC = timezone.utc
TZ4 = timezone(timedelta(hours=4))

TIME_ZONE = "Europe/Berlin"


def fixed_datetime(
    name: str,
    index: int = 0,
    timezones: Iterable[Optional[tzinfo]] = (),
) -> datetime:
    """
    Generate some datetime that is deterministically unique for the given name and index
    pair (for testing purposes). Starting with a naive datetime, convert its timezone in
    the given sequence of timezones, where `None` means naive (for conveniently
    representing the underlying timezone conversions of the tested function).
    """

    dt = datetime(2000, int(name), 1 + index)
    for tz in timezones:
        dt = dt.astimezone(tz) if tz and dt.tzinfo else dt.replace(tzinfo=tz)
    return dt


class TimeInterface(Enum):
    INTERNAL = "_"
    DJANGO = "get_"
    DJANGO_LEGACY = ""

    @property
    def names(self) -> Sequence[str]:
        return [
            f"{self.value}{attribute}_time"
            for attribute in ["accessed", "created", "modified"]
        ]


class TimeStorage(TimeStorageMixin, Storage):
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"


class NaiveTimeStorage(TimeStorage):
    def _accessed_time(self, name: str) -> datetime:
        return fixed_datetime(name, 0)

    def _created_time(self, name: str) -> datetime:
        return fixed_datetime(name, 1)

    def _modified_time(self, name: str) -> datetime:
        return fixed_datetime(name, 2)


class AwareTimeStorage(TimeStorage):
    def _accessed_time(self, name: str) -> datetime:
        return fixed_datetime(name, 0, [TZ4])

    def _created_time(self, name: str) -> datetime:
        return fixed_datetime(name, 1, [TZ4])

    def _modified_time(self, name: str) -> datetime:
        return fixed_datetime(name, 2, [TZ4])


class DefaultNaiveTimeStorage(NaiveTimeStorage):
    _default_timezone = UTC


class DefaultAwareTimeStorage(AwareTimeStorage):
    _default_timezone = UTC


class TimeStorageMixinTest(TestCase):
    storage: TimeStorage

    def setUp(self) -> None:
        self.name = "10"

    def test_not_implemented(self) -> None:
        self.storage = TimeStorage()
        for use_tz in [True, False]:
            with self.settings(USE_TZ=use_tz, TIME_ZONE=TIME_ZONE):
                self._assert_time(
                    interface=TimeInterface.INTERNAL,
                    raises=NotImplementedError,
                )
                self._assert_time(
                    interface=TimeInterface.DJANGO,
                    raises=NotImplementedError,
                )
                self._assert_time(
                    interface=TimeInterface.DJANGO_LEGACY,
                    raises=NotImplementedError,
                )

    def test_naive(self) -> None:
        self.storage = NaiveTimeStorage()
        for use_tz in [True, False]:
            with self.settings(USE_TZ=use_tz, TIME_ZONE=TIME_ZONE):
                self._assert_time(
                    interface=TimeInterface.INTERNAL,
                    timezones=[None],
                )
                self._assert_time(
                    interface=TimeInterface.DJANGO,
                    raises=NotImplementedError,
                )
                self._assert_time(
                    interface=TimeInterface.DJANGO_LEGACY,
                    timezones=[None],
                )

    def test_aware(self) -> None:
        self.storage = AwareTimeStorage()
        for use_tz in [True, False]:
            with self.settings(USE_TZ=use_tz, TIME_ZONE=TIME_ZONE):
                self._assert_time(
                    interface=TimeInterface.INTERNAL,
                    timezones=[TZ4],
                )
                self._assert_time(
                    interface=TimeInterface.DJANGO,
                    timezones=[TZ4, get_current_timezone(), TZ4 if use_tz else None],
                )
                self._assert_time(
                    interface=TimeInterface.DJANGO_LEGACY,
                    timezones=[TZ4, get_current_timezone(), None],
                )

    def test_default_over_naive(self) -> None:
        self.storage = DefaultNaiveTimeStorage()
        for use_tz in [True, False]:
            with self.settings(USE_TZ=use_tz, TIME_ZONE=TIME_ZONE):
                self._assert_time(
                    interface=TimeInterface.INTERNAL,
                    timezones=[None],
                )
                self._assert_time(
                    interface=TimeInterface.DJANGO,
                    timezones=[UTC, get_current_timezone(), UTC if use_tz else None],
                )
                self._assert_time(
                    interface=TimeInterface.DJANGO_LEGACY,
                    timezones=[UTC, get_current_timezone(), None],
                )

    def test_aware_over_default(self) -> None:
        self.storage = DefaultAwareTimeStorage()
        for use_tz in [True, False]:
            with self.settings(USE_TZ=use_tz, TIME_ZONE=TIME_ZONE):
                self._assert_time(
                    interface=TimeInterface.INTERNAL,
                    timezones=[TZ4],
                )
                self._assert_time(
                    interface=TimeInterface.DJANGO,
                    timezones=[TZ4, get_current_timezone(), TZ4 if use_tz else None],
                )
                self._assert_time(
                    interface=TimeInterface.DJANGO_LEGACY,
                    timezones=[TZ4, get_current_timezone(), None],
                )

    def _assert_time(
        self,
        interface: TimeInterface,
        raises: Optional[Type[Exception]] = None,
        timezones: Iterable[Optional[tzinfo]] = (),
    ) -> None:
        """
        Assert that the implementation of the specified time interface by the storage to
        test either raises the given exception or returns an expected datetime converted
        in the given sequence of timezones.
        """

        timezones = list(timezones)
        storage = self.storage
        name = self.name
        for i, getter_name in enumerate(interface.names):
            getter = getattr(storage, getter_name)
            if raises:
                with self.assertRaises(raises):
                    getter(name)
            else:
                actual = getter(name)
                expected = fixed_datetime(name=name, index=i, timezones=timezones)
                self.assertEqual(
                    actual,
                    expected,
                    f"{storage!r}.{getter_name}({name!r}) "
                    f"must return {expected} "
                    f"instead of {actual} "
                    f"when USE_TZ={setting('USE_TZ')}.",
                )
