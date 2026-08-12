const RTC_SEC_SHIFT: u32 = 0;
const RTC_SEC_MASK: u32 = 0x7f;
const RTC_MIN_SHIFT: u32 = 7;
const RTC_MIN_MASK: u32 = 0x7f;
const RTC_HOUR_SHIFT: u32 = 14;
const RTC_HOUR_MASK: u32 = 0x7f;
const RTC_DAY_SHIFT: u32 = 0;
const RTC_DAY_MASK: u32 = 0x3f;
const RTC_MONTH_SHIFT: u32 = 6;
const RTC_MONTH_MASK: u32 = 0x1f;
const RTC_YEAR_SHIFT: u32 = 11;
const RTC_YEAR_MASK: u32 = 0xff;

pub(crate) fn decode_rtc_datetime(time_reg: u32, date_reg: u32) -> Option<u64> {
    let second = (time_reg >> RTC_SEC_SHIFT) & RTC_SEC_MASK;
    let minute = (time_reg >> RTC_MIN_SHIFT) & RTC_MIN_MASK;
    let hour = (time_reg >> RTC_HOUR_SHIFT) & RTC_HOUR_MASK;
    let day = (date_reg >> RTC_DAY_SHIFT) & RTC_DAY_MASK;
    let month = (date_reg >> RTC_MONTH_SHIFT) & RTC_MONTH_MASK;
    let year_since_2000 = (date_reg >> RTC_YEAR_SHIFT) & RTC_YEAR_MASK;

    if !(1..=99).contains(&year_since_2000) {
        return None;
    }

    datetime_to_unix_timestamp(
        2000 + year_since_2000 as i32,
        month,
        day,
        hour,
        minute,
        second,
    )
}

pub(crate) fn select_boot_epoch(rtc_epoch: Option<u64>, build_epoch: u64) -> (u64, bool) {
    match rtc_epoch {
        Some(epoch) if epoch >= build_epoch => (epoch, true),
        _ => (build_epoch, false),
    }
}

fn datetime_to_unix_timestamp(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<u64> {
    if !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)?).contains(&day)
        || hour >= 24
        || minute >= 60
        || second >= 60
        || year < 1970
    {
        return None;
    }

    let days_before_year = (1970..year).map(days_in_year).sum::<u64>();
    let days_before_month = (1..month)
        .map(|month| days_in_month(year, month).expect("validated month range"))
        .sum::<u32>() as u64;
    let days = days_before_year + days_before_month + u64::from(day - 1);
    Some(days * 86_400 + u64::from(hour) * 3_600 + u64::from(minute) * 60 + u64::from(second))
}

fn days_in_year(year: i32) -> u64 {
    if is_leap_year(year) { 366 } else { 365 }
}

fn days_in_month(year: i32, month: u32) -> Option<u32> {
    Some(match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return None,
    })
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn time_reg(hour: u32, minute: u32, second: u32) -> u32 {
        second | (minute << RTC_MIN_SHIFT) | (hour << RTC_HOUR_SHIFT)
    }

    fn date_reg(year_since_2000: u32, month: u32, day: u32) -> u32 {
        day | (month << RTC_MONTH_SHIFT) | (year_since_2000 << RTC_YEAR_SHIFT)
    }

    #[test]
    fn decodes_valid_jh7110_wall_clock() {
        assert_eq!(
            decode_rtc_datetime(time_reg(8, 34, 56), date_reg(25, 6, 12)),
            Some(1_749_717_296)
        );
    }

    #[test]
    fn rejects_invalid_jh7110_wall_clock_fields() {
        assert_eq!(
            decode_rtc_datetime(time_reg(8, 34, 56), date_reg(25, 13, 12)),
            None
        );
        assert_eq!(
            decode_rtc_datetime(time_reg(8, 34, 56), date_reg(25, 2, 30)),
            None
        );
        assert_eq!(
            decode_rtc_datetime(time_reg(24, 0, 0), date_reg(25, 6, 12)),
            None
        );
    }

    #[test]
    fn accepts_leap_day_and_rejects_unrepresentable_years() {
        assert_eq!(
            decode_rtc_datetime(time_reg(0, 0, 0), date_reg(24, 2, 29)),
            Some(1_709_164_800)
        );
        assert_eq!(
            decode_rtc_datetime(time_reg(0, 0, 0), date_reg(0, 1, 1)),
            None
        );
        assert_eq!(
            decode_rtc_datetime(time_reg(0, 0, 0), date_reg(100, 1, 1)),
            None
        );
    }

    #[test]
    fn build_epoch_is_a_lower_bound_for_non_persistent_rtc() {
        const BUILD_EPOCH: u64 = 1_786_377_600;

        assert_eq!(select_boot_epoch(None, BUILD_EPOCH), (BUILD_EPOCH, false));
        assert_eq!(
            select_boot_epoch(Some(978_307_200), BUILD_EPOCH),
            (BUILD_EPOCH, false)
        );
        assert_eq!(
            select_boot_epoch(Some(BUILD_EPOCH + 60), BUILD_EPOCH),
            (BUILD_EPOCH + 60, true)
        );
    }
}
