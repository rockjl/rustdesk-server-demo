
pub fn instant_to_naive_datetime(instant: std::time::Instant) -> chrono::NaiveDateTime {
    let duration_since_epoch = instant.duration_since(std::time::Instant::now());
    let system_now = std::time::SystemTime::now() + duration_since_epoch;
    let utc_datetime: chrono::DateTime<chrono::Utc> = system_now.into();
    utc_datetime.naive_utc()
}