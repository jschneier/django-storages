from datetime import datetime
from datetime import tzinfo
from typing import Optional

from django.utils.timezone import is_aware
from django.utils.timezone import is_naive
from django.utils.timezone import make_aware
from django.utils.timezone import make_naive

from storages.utils import setting


class TimeStorageMixin:
    """
    Mixin for handling time metadata from storage backends.

    Supports both the current and the legacy Django interfaces for time metadata:

    - `get_*_time`: Available since Django version 1.8. Handles timezones.
    - `*_time`: Deprecated since Django version 1.8 and removed in Django version 2.0.
      Always returns naive datetime values without guarantee of timezone stability.
      Despite that, it may still be useful for storage backends relying on technology
      that does not provide timezone information and therefore cannot implement the new,
      timezone-aware interface.

    Subclasses may handle both simply by implementing the internal `_*_time` interfaces
    (note the leading underscore). Returning an aware datetime enables both interfaces,
    whereas returning a naive datetime enables only the legacy interface.

    If known, `_default_timezone` may be set to ensure every datetime returned by the
    internal interface implementations is aware. However, due to the possibility of DST
    ambiguities, this approach is correct only for a timezone without DST, such as UTC.
    Otherwise, more sophisticated conversion methods must be realized by overriding
    `_aware_time`.
    """

    _default_timezone: Optional[tzinfo] = None
    """The timezone to attach in case the storage backend returns a naive datetime."""

    # current Django interface

    def get_accessed_time(self, name: str) -> datetime:
        return self._get_time(self._accessed_time(name))

    def get_created_time(self, name: str) -> datetime:
        return self._get_time(self._created_time(name))

    def get_modified_time(self, name: str) -> datetime:
        return self._get_time(self._modified_time(name))

    # legacy Django interface

    def accessed_time(self, name: str) -> datetime:
        return self._naive_time(self._accessed_time(name))

    def created_time(self, name: str) -> datetime:
        return self._naive_time(self._created_time(name))

    def modified_time(self, name: str) -> datetime:
        return self._naive_time(self._modified_time(name))

    # internal interface

    def _accessed_time(self, name: str) -> datetime:
        raise NotImplementedError("Storage backend does not support accessed time.")

    def _created_time(self, name: str) -> datetime:
        raise NotImplementedError("Storage backend does not support created time.")

    def _modified_time(self, name: str) -> datetime:
        raise NotImplementedError("Storage backend does not support modified time.")

    # internal helpers

    def _get_time(self, dt: datetime) -> datetime:
        """
        Turn any datetime (naive or aware) into an aware or naive datetime, depending
        on the value of Django's USE_TZ setting. The resulting naive datetime must be in
        Django's current timezone.
        """

        dt = self._aware_time(dt)
        return dt if setting("USE_TZ") else make_naive(dt)

    def _naive_time(self, dt: datetime) -> datetime:
        """
        Turn any datetime (naive or aware) into a naive datetime. The resulting naive
        datetime should be in Django's current timezone in case timezone information is
        available (i.e., the timezone is already aware or a default timezone is set).
        """

        try:
            dt = self._aware_time(dt)
        except NotImplementedError:
            pass
        return dt if is_naive(dt) else make_naive(dt)

    def _aware_time(self, dt: datetime) -> datetime:
        """
        Turn any datetime (naive or aware) into an aware datetime in any timezone,
        taking into account additional timezone information such as the default
        timezone if it is set.
        """

        if is_aware(dt):
            return dt
        default_timezone = self._default_timezone
        if default_timezone is None:
            raise NotImplementedError("Missing timezone information.")
        return make_aware(dt, timezone=default_timezone)
