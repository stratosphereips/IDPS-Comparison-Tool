from datetime import datetime, timezone
from re import findall

class TimestampHandler():

    def convert_to_human_readable(self, unix_ts):
        datetime_obj = datetime.fromtimestamp(float(unix_ts))
        return datetime_obj.strftime('%Y-%m-%d %H:%M:%S')

    def convert_iso_8601_to_unix_timestamp(self, ts: str, tz=False) -> float:
        """
        converts iso 8601 format to unix timestamp
        expected format: %Y-%m-%dT%H:%M:%S.%f%z
        :param ts: ts in expected format
        :param tz: if true, we set the tz to utc
        :return: the given ts in unix format
        """
        dt = datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%f%z')

        if tz:
            # convert datetime to time-aware timezone at UTC
            # so correct timestamp is returned
            dt = dt.replace(tzinfo=timezone.utc)


        # Return the time in seconds since the epoch
        seconds_since_epoch = dt.timestamp()

        return seconds_since_epoch

    def assert_microseconds(self, ts: str):
        """
        adds microseconds to the given ts if not present
        :param ts: unix ts
        :return: ts
        """
        if not self.is_unix_timestamp(ts):
            ts = self.convert_iso_8601_to_unix_timestamp(ts)

        ts = str(ts)
        # pattern of unix ts with microseconds
        pattern = r'\b\d+\.\d{6}\b'
        matches = findall(pattern, ts)

        if not matches:
            # fill the missing microseconds and milliseconds with 0
            # 6 is the decimals we need after the . in the unix ts
            ts = ts + "0" * (6 - len(ts.split('.')[-1]))
        return ts



    def is_unix_timestamp(self, s):
        try:
            # Convert the string to a floating-point number
            timestamp = float(s)

            # Check if the timestamp is non-negative
            if timestamp < 0:
                return False

            # Check if the string is composed of only digits and optional decimal point
            if not str(s).replace(".", "").isdigit():
                return False

            return True

        except ValueError:
            return False

    def remove_milliseconds(self, ts) -> str:
        """
        remove the milliseconds from the given ts
        :param ts: time in unix format
        """
        ts = str(ts)
        if '.' not in ts:
            return ts

        return ts.split('.')[0]

    def remove_microseconds(self, ts) -> str:
        """
        remove the microsecinds from the given ts
        :param ts: time in unix format
        """
        ts = str(ts)
        if '.' not in ts:
            return ts

        before_decimal, after_decimal = ts.split('.')
        if len(after_decimal) != 6:
            # doesn't have microseconds to remove them
            return ts

        return f"{before_decimal}.{after_decimal[:4]}"
