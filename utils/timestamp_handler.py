from datetime import datetime, timezone


class TimestampHandler():
    def convert_iso_8601_to_unix_timestamp(self, ts: str) -> float:
        """
        converts iso 8601 format to unix timestamp
        expected format: %Y-%m-%dT%H:%M:%S.%f%z
        :param ts: ts in expected format
        :return: the given ts in unix format
        """
        dt = datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%f%z')

        # convert datetime to time-aware timezone at UTC
        # so correct timestamp is returned
        dt = dt.replace(tzinfo=timezone.utc)

        # Return the time in seconds since the epoch
        seconds_since_epoch = dt.timestamp()

        return seconds_since_epoch

    def is_unix_timestamp(self, s):
        try:
            # Convert the string to a floating-point number
            timestamp = float(s)

            # Check if the timestamp is non-negative
            if timestamp < 0:
                return False

            # Check if the string is composed of only digits and optional decimal point
            if not s.replace(".", "").isdigit():
                return False

            return True

        except ValueError:
            return False

    def remove_milliseconds_decimals(self, ts: str) -> str:
        """
        remove the milliseconds from the given ts
        :param ts: time in unix format
        """
        ts = str(ts)
        if '.' not in ts:
            return ts

        return ts.split('.')[0]
