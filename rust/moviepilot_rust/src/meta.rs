use crate::utils::{apply_range_total, capture_all_i64, capture_i64};
use once_cell::sync::Lazy;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use regex::{Regex, RegexBuilder};

static ANIME_BRACKET_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"【[+0-9XVPI-]+】\s*【")
        .case_insensitive(true)
        .build()
        .unwrap()
});
static ANIME_DASH_EPISODE_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"\s+-\s+[\dv]{1,4}\s+")
        .case_insensitive(true)
        .build()
        .unwrap()
});
static VIDEO_SEASON_EPISODE_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(
        r"S\d{2}\s*-\s*S\d{2}|S\d{2}|\s+S\d{1,2}|EP?\d{2,4}\s*-\s*EP?\d{2,4}|EP?\d{2,4}|\s+EP?\d{1,4}",
    )
    .case_insensitive(true)
    .build()
    .unwrap()
});
static ANIME_SQUARE_BRACKET_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"\[[+0-9XVPI-]+]\s*\[")
        .case_insensitive(true)
        .build()
        .unwrap()
});
static BRACED_METAINFO_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\{\[([\s\S]+?)]}").unwrap());
static BRACED_TMDBID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"tmdbid=(\d+)").unwrap());
static BRACED_DOUBANID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"doubanid=(\d+)").unwrap());
static BRACED_TYPE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"type=(\w+)").unwrap());
static BRACED_BEGIN_SEASON_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?:^|;)s=(\d+)").unwrap());
static BRACED_END_SEASON_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"s=\d+-(\d+)").unwrap());
static BRACED_BEGIN_EPISODE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?:^|;)e=(\d+)").unwrap());
static BRACED_END_EPISODE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"e=\d+-(\d+)").unwrap());
static EMBY_TMDB_RE_LIST: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"\[tmdbid[=\-](\d+)]").unwrap(),
        Regex::new(r"\[tmdb[=\-](\d+)]").unwrap(),
        Regex::new(r"\{tmdbid[=\-](\d+)}").unwrap(),
        Regex::new(r"\{tmdb[=\-](\d+)}").unwrap(),
    ]
});

static TITLE_SIZE_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"[0-9.]+\s*[MGT]i?B")
        .case_insensitive(true)
        .build()
        .unwrap()
});
static TITLE_DATE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\d{4}[\s._-]\d{1,2}[\s._-]\d{1,2}").unwrap());
static TITLE_YEAR_RANGE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([\s.]+)(\d{4})-(\d{4})").unwrap());
static FIRST_BRACKET_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[\[【](.+?)[\]】]").unwrap());
static FIRST_BRACKET_RELEASE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Za-z]+\..+(?:19|20)\d{2}").unwrap());
static FIRST_BRACKET_RESOURCE_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"(?:2160|1080|720|480)[PIpi]|4K|UHD|Blu[\-.]?ray|REMUX|WEB[\-.]?DL|HDTV")
        .case_insensitive(true)
        .build()
        .unwrap()
});
static TOKEN_SPLIT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[.\s()\[\]\-【】/～;&|#_「」~]+").unwrap());
static FULL_SEASON_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"^(?:Season\s+|S)(\d{1,3})$")
        .case_insensitive(true)
        .build()
        .unwrap()
});
static SEASON_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"S(\d{3})|^S(\d{1,3})$|S(\d{1,3})E")
        .case_insensitive(true)
        .build()
        .unwrap()
});
static EPISODE_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"EP?(\d{2,4})$|^EP?(\d{1,4})$|^S\d{1,2}EP?(\d{1,4})$|S\d{2}EP?(\d{2,4})")
        .case_insensitive(true)
        .build()
        .unwrap()
});
static RESOURCE_PIX_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"^[SBUHD]*(\d{3,4}[PI]+)|\d{3,4}X(\d{3,4})")
        .case_insensitive(true)
        .build()
        .unwrap()
});
static RESOURCE_PIX_RE2: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"(^[248]+K)")
        .case_insensitive(true)
        .build()
        .unwrap()
});
static SOURCE_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"^BLURAY$|^HDTV$|^UHDTV$|^HDDVD$|^WEBRIP$|^DVDRIP$|^BDRIP$|^BLU$|^WEB$|^BD$|^HDRip$|^REMUX$|^UHD$")
        .case_insensitive(true)
        .build()
        .unwrap()
});
static EFFECT_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(
        r"^SDR$|^HDR\d*$|^DOLBY$|^DOVI$|^DV$|^3D$|^REPACK$|^HLG$|^HDR10(\+|Plus)$|^EDR$|^HQ$",
    )
    .case_insensitive(true)
    .build()
    .unwrap()
});
static VIDEO_ENCODE_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"^(H26[45])$|^(x26[45])$|^AVC$|^HEVC$|^VC\d?$|^MPEG\d?$|^Xvid$|^DivX$|^AV1$|^HDR\d*$|^AVS(\+|[23])$")
        .case_insensitive(true)
        .build()
        .unwrap()
});
static AUDIO_ENCODE_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"^DTS\d?$|^DTSHD$|^DTSHDMA$|^Atmos$|^TrueHD\d?$|^AC3$|^\dAudios?$|^DDP\d?$|^DD\+\d?$|^DD\d?$|^LPCM\d?$|^AAC\d?$|^FLAC\d?$|^HD\d?$|^MA\d?$|^HR\d?$|^Opus\d?$|^Vorbis\d?$|^AV[3S]A$")
        .case_insensitive(true)
        .build()
        .unwrap()
});
static FPS_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"(\d{2,3})FPS")
        .case_insensitive(true)
        .build()
        .unwrap()
});
static PART_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(
        r"(^PART[0-9ABI]{0,2}$|^CD[0-9]{0,2}$|^DVD[0-9]{0,2}$|^DISK[0-9]{0,2}$|^DISC[0-9]{0,2}$)",
    )
    .case_insensitive(true)
    .build()
    .unwrap()
});
static NAME_NO_CHINESE_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r".*版|.*字幕")
        .case_insensitive(true)
        .build()
        .unwrap()
});
static VIDEO_BIT_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"(?i)(8|10|12)[\s._-]*bit")
        .build()
        .unwrap()
});

struct VideoParseState {
    tokens: Vec<String>,
    media_exts: Vec<String>,
    isfile: bool,
    cn_name: Option<String>,
    en_name: Option<String>,
    year: Option<String>,
    total_season: i64,
    begin_season: Option<i64>,
    end_season: Option<i64>,
    total_episode: i64,
    begin_episode: Option<i64>,
    end_episode: Option<i64>,
    part: Option<String>,
    source: String,
    effects: Vec<String>,
    resource_pix: Option<String>,
    web_source: Option<String>,
    video_encode: Option<String>,
    video_bit: Option<String>,
    audio_encode: Option<String>,
    fps: Option<i64>,
    media_type: Option<String>,
    stop_name_flag: bool,
    stop_cnname_flag: bool,
    last_token: String,
    last_token_type: String,
    continue_flag: bool,
    unknown_name_str: String,
    index: usize,
}

#[pyfunction]
pub(crate) fn is_anime_fast(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if ANIME_BRACKET_RE.is_match(name) {
        return true;
    }
    if ANIME_DASH_EPISODE_RE.is_match(name) {
        return true;
    }
    if VIDEO_SEASON_EPISODE_RE.is_match(name) {
        return false;
    }
    ANIME_SQUARE_BRACKET_RE.is_match(name)
}

/// 从标题中的内嵌标签提取媒体 ID、类型和季集范围。
#[pyfunction]
pub(crate) fn find_metainfo_fast(py: Python<'_>, title: &str) -> PyResult<PyObject> {
    let result = PyDict::new(py);
    let mut cleaned_title = title.to_string();
    let mut tmdbid: Option<String> = None;
    let mut doubanid: Option<String> = None;
    let mut media_type: Option<String> = None;
    let mut begin_season: Option<i64> = None;
    let mut end_season: Option<i64> = None;
    let mut begin_episode: Option<i64> = None;
    let mut end_episode: Option<i64> = None;

    for captures in BRACED_METAINFO_RE.captures_iter(title) {
        let Some(meta_match) = captures.get(1) else {
            continue;
        };
        let meta_text = meta_match.as_str();
        let found_tmdb = BRACED_TMDBID_RE
            .captures(meta_text)
            .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()));
        if found_tmdb.is_some() {
            tmdbid = found_tmdb.clone();
        }
        if let Some(value) = BRACED_DOUBANID_RE
            .captures(meta_text)
            .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
        {
            doubanid = Some(value);
        }
        let found_type = BRACED_TYPE_RE
            .captures(meta_text)
            .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()));
        if let Some(value) = found_type.as_deref() {
            if value == "movies" || value == "tv" {
                media_type = Some(value.to_string());
            }
        }
        if let Some(value) = capture_i64(&BRACED_BEGIN_SEASON_RE, meta_text) {
            begin_season = Some(value);
        }
        if let Some(value) = capture_i64(&BRACED_END_SEASON_RE, meta_text) {
            end_season = Some(value);
        }
        if let Some(value) = capture_i64(&BRACED_BEGIN_EPISODE_RE, meta_text) {
            begin_episode = Some(value);
        }
        if let Some(value) = capture_i64(&BRACED_END_EPISODE_RE, meta_text) {
            end_episode = Some(value);
        }
        if found_tmdb.is_some()
            || found_type.is_some()
            || begin_season.is_some()
            || end_season.is_some()
            || begin_episode.is_some()
            || end_episode.is_some()
        {
            cleaned_title = cleaned_title.replace(&format!("{{[{meta_text}]}}"), "");
        }
    }

    if let Some(caps) = EMBY_TMDB_RE_LIST[0].captures(&cleaned_title) {
        tmdbid = caps.get(1).map(|m| m.as_str().to_string());
        cleaned_title = EMBY_TMDB_RE_LIST[0]
            .replace_all(&cleaned_title, "")
            .trim()
            .to_string();
    } else if tmdbid.is_none() {
        for tmdb_re in EMBY_TMDB_RE_LIST.iter().skip(1) {
            if let Some(caps) = tmdb_re.captures(&cleaned_title) {
                tmdbid = caps.get(1).map(|m| m.as_str().to_string());
                cleaned_title = tmdb_re.replace_all(&cleaned_title, "").trim().to_string();
                break;
            }
        }
    }

    let (begin_season, end_season, total_season) = apply_range_total(begin_season, end_season);
    let (begin_episode, end_episode, total_episode) = apply_range_total(begin_episode, end_episode);

    result.set_item("title", cleaned_title)?;
    result.set_item("tmdbid", tmdbid)?;
    result.set_item("doubanid", doubanid)?;
    result.set_item("type", media_type)?;
    result.set_item("begin_season", begin_season)?;
    result.set_item("end_season", end_season)?;
    result.set_item("total_season", total_season)?;
    result.set_item("begin_episode", begin_episode)?;
    result.set_item("end_episode", end_episode)?;
    result.set_item("total_episode", total_episode)?;
    Ok(result.into())
}

/// 对标题执行影视主识别流程，返回名称、季集、资源和编码等完整主状态。
#[pyfunction]
#[pyo3(signature = (title, isfile=false, media_exts=None))]
pub(crate) fn parse_video_title_fast(
    py: Python<'_>,
    title: &str,
    isfile: bool,
    media_exts: Option<Vec<String>>,
) -> PyResult<PyObject> {
    let result = PyDict::new(py);
    if title.is_empty() {
        result.set_item("complete", false)?;
        return Ok(result.into());
    }

    if isfile && title.chars().all(|ch| ch.is_ascii_digit()) && title.len() < 5 {
        result.set_item("complete", true)?;
        result.set_item("type", "tv")?;
        result.set_item("begin_episode", title.parse::<i64>().ok())?;
        result.set_item("total_episode", 1)?;
        return Ok(result.into());
    }

    if let Some(caps) = FULL_SEASON_RE.captures(title) {
        result.set_item("complete", true)?;
        result.set_item("type", "tv")?;
        if let Some(season) = caps
            .get(1)
            .and_then(|value| value.as_str().parse::<i64>().ok())
        {
            result.set_item("begin_season", season)?;
            result.set_item("total_season", 1)?;
        }
        return Ok(result.into());
    }

    let normalized = normalize_video_title(title);
    let tokens: Vec<String> = TOKEN_SPLIT_RE
        .split(&normalized)
        .filter(|token| !token.is_empty())
        .map(|token| token.to_string())
        .collect();

    let mut parser = VideoParseState::new(tokens, isfile, media_exts.unwrap_or_default());
    parser.parse();
    let mut effects = parser.effects.clone();
    if !effects.is_empty() {
        effects.reverse();
    }

    result.set_item("complete", true)?;
    result.set_item("cn_name", parser.cn_name)?;
    result.set_item("en_name", parser.en_name)?;
    result.set_item("year", parser.year)?;
    result.set_item("type", parser.media_type)?;
    result.set_item("begin_season", parser.begin_season)?;
    result.set_item("end_season", parser.end_season)?;
    result.set_item(
        "total_season",
        if parser.total_season > 0 {
            Some(parser.total_season)
        } else {
            None
        },
    )?;
    result.set_item("begin_episode", parser.begin_episode)?;
    result.set_item("end_episode", parser.end_episode)?;
    result.set_item(
        "total_episode",
        if parser.total_episode > 0 {
            Some(parser.total_episode)
        } else {
            None
        },
    )?;
    result.set_item("part", parser.part)?;
    result.set_item(
        "resource_type",
        if parser.source.is_empty() {
            None
        } else {
            Some(parser.source.trim().to_string())
        },
    )?;
    result.set_item(
        "resource_effect",
        if effects.is_empty() {
            None
        } else {
            Some(effects.join(" "))
        },
    )?;
    result.set_item("resource_pix", parser.resource_pix)?;
    result.set_item("web_source", parser.web_source)?;
    result.set_item("video_encode", parser.video_encode)?;
    result.set_item("video_bit", parser.video_bit)?;
    result.set_item("audio_encode", parser.audio_encode)?;
    result.set_item("fps", parser.fps)?;
    Ok(result.into())
}

fn normalize_video_title(title: &str) -> String {
    let mut value = title.to_string();
    if let Some(caps) = FIRST_BRACKET_RE.captures(&value) {
        if let Some(content) = caps.get(1) {
            if FIRST_BRACKET_RELEASE_RE.is_match(content.as_str())
                && FIRST_BRACKET_RESOURCE_RE.is_match(content.as_str())
            {
                value = format!(
                    "{}{}",
                    content.as_str(),
                    value
                        .get(caps.get(0).map(|m| m.end()).unwrap_or(0)..)
                        .unwrap_or("")
                );
            } else if let Some(full) = caps.get(0) {
                value = value.get(full.end()..).unwrap_or("").to_string();
            }
        }
    }
    value = TITLE_YEAR_RANGE_RE.replace_all(&value, "$1$2").to_string();
    value = remove_title_size_markers(&value);
    TITLE_DATE_RE.replace_all(&value, "").to_string()
}

/// 移除标题里的大小标记；单位后紧跟大写字母时保留，兼容 Python 负向前瞻语义。
fn remove_title_size_markers(title: &str) -> String {
    TITLE_SIZE_RE
        .replace_all(title, |caps: &regex::Captures<'_>| {
            let Some(matched) = caps.get(0) else {
                return String::new();
            };
            let next_char = title
                .get(matched.end()..)
                .and_then(|tail| tail.chars().next());
            if next_char.is_some_and(|ch| ch.is_ascii_uppercase()) {
                matched.as_str().to_string()
            } else {
                String::new()
            }
        })
        .to_string()
}

/// 识别分辨率字段。
fn parse_resource_pix(token: &str) -> Option<String> {
    if let Some(caps) = RESOURCE_PIX_RE.captures(token) {
        for item in caps.iter().skip(1).flatten() {
            let mut pix = item.as_str().to_lowercase();
            if pix.chars().all(|ch| ch.is_ascii_digit()) && !pix.ends_with(['k', 'p', 'i']) {
                pix.push('p');
            }
            return Some(pix);
        }
    }
    RESOURCE_PIX_RE2
        .captures(token)
        .and_then(|caps| caps.get(1).map(|item| item.as_str().to_lowercase()))
}

/// 判断文本是否包含中日韩统一表意文字，等价于 Python StringUtils.is_chinese。
fn contains_chinese(text: &str) -> bool {
    text.chars()
        .any(|ch| ('\u{4e00}'..='\u{9fff}').contains(&ch))
}

/// 判断 token 是否属于季集描述词。
fn is_name_se_word(token: &str) -> bool {
    matches!(token, "共" | "第" | "季" | "集" | "话" | "話" | "期")
}

/// 判断 token 是否包含季集描述词。
fn contains_name_se_word(token: &str) -> bool {
    ["共", "第", "季", "集", "话", "話", "期"]
        .iter()
        .any(|word| token.contains(word))
}

/// 判断中文 token 是否表示剧场版/电影版，保留在中文名中。
fn is_name_movie_word(token: &str) -> bool {
    ["剧场版", "劇場版", "电影版", "電影版"]
        .iter()
        .any(|word| token.contains(word))
}

/// 判断罗马数字，覆盖 Python 原正则的合法罗马数字范围。
fn is_roman_numeral(token: &str) -> bool {
    let upper = token.to_uppercase();
    if upper.is_empty()
        || !upper
            .chars()
            .all(|ch| matches!(ch, 'M' | 'D' | 'C' | 'L' | 'X' | 'V' | 'I'))
    {
        return false;
    }
    let mut prev = 0;
    let mut total = 0;
    for ch in upper.chars().rev() {
        let value = match ch {
            'I' => 1,
            'V' => 5,
            'X' => 10,
            'L' => 50,
            'C' => 100,
            'D' => 500,
            'M' => 1000,
            _ => 0,
        };
        if value < prev {
            total -= value;
        } else {
            total += value;
            prev = value;
        }
    }
    total > 0
}

/// 判断字符串是否以指定 ASCII 后缀结尾，忽略大小写。
fn ends_with_ignore_ascii(value: &str, suffix: &str) -> bool {
    value
        .get(value.len().saturating_sub(suffix.len())..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

/// 用空格向可选字符串追加片段。
fn append_with_space(target: &mut Option<String>, value: &str) {
    if value.is_empty() {
        return;
    }
    match target {
        Some(existing) if !existing.is_empty() => {
            existing.push(' ');
            existing.push_str(value);
        }
        _ => *target = Some(value.to_string()),
    }
}

/// 原样追加片段，用于保留 Python 中 Season 标题后置空格的兼容行为。
fn append_raw(target: &mut Option<String>, value: &str) {
    if let Some(existing) = target {
        existing.push_str(value);
    }
}

/// 识别常见流媒体平台简称和全称。
fn streaming_platform_name(token: &str) -> Option<&'static str> {
    let normalized = token.to_uppercase();
    match normalized.as_str() {
        "AMZN" | "AMAZON" => Some("Amazon"),
        "NF" | "NETFLIX" => Some("Netflix"),
        "ATVP" | "APPLE TV+" | "APPLE-TV+" => Some("Apple TV+"),
        "DSNP" | "DISNEY+" | "DISNEY" => Some("Disney+"),
        "HMAX" | "MAX" => Some("Max"),
        "HULU" => Some("Hulu Networks"),
        "PMTP" | "PARAMOUNT+" | "PARAMOUNT" => Some("Paramount+"),
        "PCOK" | "PEACOCK" => Some("Peacock"),
        "B-GLOBAL" | "BG" => Some("B-Global"),
        "BAHA" => Some("Baha"),
        "CR" | "CRUNCHYROLL" => Some("Crunchyroll"),
        "VIU" => Some("Viu"),
        "ITUNES" | "IT" => Some("iTunes"),
        "YOUTUBE" | "YT" => Some("YouTube"),
        "ROKU" => Some("Roku"),
        "PLEX" => Some("Plex"),
        "STAN" => Some("Stan"),
        _ => None,
    }
}

/// 识别片源和效果字段，并保留 BluRay/WEB-DL/REMUX 等组合语义。

fn normalize_source(token: &str) -> String {
    if token.eq_ignore_ascii_case("BLURAY") {
        return "BluRay".to_string();
    }
    if token.eq_ignore_ascii_case("WEBDL") {
        return "WEB-DL".to_string();
    }
    token.to_string()
}

fn parse_video_bit(token: &str) -> Option<String> {
    VIDEO_BIT_RE
        .captures(token)
        .and_then(|caps| caps.get(1).map(|value| format!("{}bit", value.as_str())))
}

/// 标准化视频编码捕获结果，保持 Python MetaVideo 的大小写兼容行为。
fn normalize_video_encode_capture(caps: &regex::Captures<'_>) -> Option<String> {
    let value = caps.get(0)?.as_str();
    if value.starts_with('x') || value.starts_with('X') {
        return Some(value.to_lowercase());
    }
    Some(value.to_uppercase())
}

impl VideoParseState {
    /// 创建影视标题主解析状态机，保持 Python MetaVideo 原有字段和中间状态语义。
    fn new(tokens: Vec<String>, isfile: bool, media_exts: Vec<String>) -> Self {
        Self {
            tokens,
            media_exts: media_exts
                .into_iter()
                .map(|item| item.to_lowercase())
                .collect(),
            isfile,
            cn_name: None,
            en_name: None,
            year: None,
            total_season: 0,
            begin_season: None,
            end_season: None,
            total_episode: 0,
            begin_episode: None,
            end_episode: None,
            part: None,
            source: String::new(),
            effects: Vec::new(),
            resource_pix: None,
            web_source: None,
            video_encode: None,
            video_bit: None,
            audio_encode: None,
            fps: None,
            media_type: None,
            stop_name_flag: false,
            stop_cnname_flag: false,
            last_token: String::new(),
            last_token_type: String::new(),
            continue_flag: true,
            unknown_name_str: String::new(),
            index: 0,
        }
    }

    /// 执行单轮 token 扫描，迁移 Python 侧 MetaVideo.__init__ 的主循环。
    fn parse(&mut self) {
        while self.index < self.tokens.len() {
            let token = self.tokens[self.index].clone();
            self.index += 1;
            self.parse_part(&token);
            if self.continue_flag {
                self.parse_name(&token);
            }
            if self.continue_flag {
                self.parse_year(&token);
            }
            if self.continue_flag {
                self.parse_resource_pix(&token);
            }
            if self.continue_flag {
                self.parse_season(&token);
            }
            if self.continue_flag {
                self.parse_episode(&token);
            }
            if self.continue_flag {
                self.parse_resource_type(&token);
            }
            if self.continue_flag {
                self.parse_streaming_platform(&token);
            }
            if self.continue_flag {
                self.parse_video_encode(&token);
            }
            if self.continue_flag {
                self.parse_video_bit(&token);
            }
            if self.continue_flag {
                self.parse_audio_encode(&token);
            }
            if self.continue_flag {
                self.parse_fps(&token);
            }
            self.continue_flag = true;
        }
    }

    /// 返回当前是否已经识别到任意名称。
    fn has_name(&self) -> bool {
        self.cn_name
            .as_deref()
            .is_some_and(|value| !value.is_empty())
            || self
                .en_name
                .as_deref()
                .is_some_and(|value| !value.is_empty())
    }

    /// 识别标题中的 Part/CD/DVD/Disc 信息。
    fn parse_part(&mut self, token: &str) {
        if !self.has_name()
            || (self.year.is_none()
                && self.begin_season.is_none()
                && self.begin_episode.is_none()
                && self.resource_pix.is_none()
                && self.source.is_empty())
        {
            return;
        }
        let Some(caps) = PART_RE.captures(token) else {
            return;
        };
        if self.part.is_none() {
            self.part = caps.get(1).map(|value| value.as_str().to_string());
        }
        if let Some(next_value) = self.tokens.get(self.index) {
            let upper = next_value.to_uppercase();
            let next_is_part_suffix = (next_value.chars().all(|ch| ch.is_ascii_digit())
                && (next_value.len() == 1
                    || (next_value.len() == 2 && next_value.starts_with('0'))))
                || matches!(upper.as_str(), "A" | "B" | "C" | "I" | "II" | "III");
            if next_is_part_suffix {
                if let Some(part) = &mut self.part {
                    part.push_str(next_value);
                }
                self.index += 1;
            }
        }
        self.last_token_type = "part".to_string();
        self.continue_flag = false;
    }

    /// 识别中文名和英文名，保持原有停止名称消费的规则。
    fn parse_name(&mut self, token: &str) {
        if token.is_empty() {
            return;
        }
        if !self.unknown_name_str.is_empty() {
            if self.cn_name.as_deref().unwrap_or("").is_empty() {
                if self.en_name.as_deref().unwrap_or("").is_empty() {
                    self.en_name = Some(self.unknown_name_str.clone());
                } else if Some(self.unknown_name_str.as_str()) != self.year.as_deref() {
                    append_with_space(&mut self.en_name, &self.unknown_name_str);
                }
                self.last_token_type = "enname".to_string();
            }
            self.unknown_name_str.clear();
        }
        if self.stop_name_flag {
            return;
        }
        if token.eq_ignore_ascii_case("AKA") {
            self.continue_flag = false;
            self.stop_name_flag = true;
            return;
        }
        if is_name_se_word(token) {
            self.last_token_type = "name_se_words".to_string();
            return;
        }
        if contains_chinese(token) {
            self.last_token_type = "cnname".to_string();
            if self.cn_name.as_deref().unwrap_or("").is_empty() {
                self.cn_name = Some(token.to_string());
            } else if !self.stop_cnname_flag {
                if is_name_movie_word(token)
                    || (!NAME_NO_CHINESE_RE.is_match(token) && !contains_name_se_word(token))
                {
                    append_with_space(&mut self.cn_name, token);
                }
                self.stop_cnname_flag = true;
            }
            return;
        }

        let roman_digit = is_roman_numeral(token);
        if token.chars().all(|ch| ch.is_ascii_digit()) || roman_digit {
            if self.last_token_type == "name_se_words" {
                return;
            }
            if self.has_name() {
                if token.starts_with('0') {
                    return;
                }
                if token.chars().all(|ch| ch.is_ascii_digit())
                    && self.last_token_type == "cnname"
                    && token.parse::<i64>().ok().is_some_and(|value| value < 1900)
                {
                    return;
                }
                if (token.chars().all(|ch| ch.is_ascii_digit()) && token.len() < 4) || roman_digit {
                    if self.last_token_type == "cnname" {
                        append_with_space(&mut self.cn_name, token);
                    } else if self.last_token_type == "enname" {
                        append_with_space(&mut self.en_name, token);
                    }
                    self.continue_flag = false;
                } else if token.chars().all(|ch| ch.is_ascii_digit())
                    && token.len() == 4
                    && self.unknown_name_str.is_empty()
                {
                    self.unknown_name_str = token.to_string();
                }
            } else if self.unknown_name_str.is_empty() {
                self.unknown_name_str = token.to_string();
            }
        } else if SEASON_RE.is_match(token) {
            if self
                .en_name
                .as_deref()
                .is_some_and(|name| ends_with_ignore_ascii(name, "SEASON"))
            {
                append_raw(&mut self.en_name, " ");
            }
            self.stop_name_flag = true;
        } else if EPISODE_RE.is_match(token)
            || SOURCE_RE.is_match(token)
            || EFFECT_RE.is_match(token)
            || RESOURCE_PIX_RE.is_match(token)
        {
            self.stop_name_flag = true;
        } else {
            if self.is_media_ext(token) {
                return;
            }
            append_with_space(&mut self.en_name, token);
            self.last_token_type = "enname".to_string();
        }
    }

    /// 识别年份；识别到年份后停止后续名称消费。
    fn parse_year(&mut self, token: &str) {
        if !self.has_name()
            || !token.chars().all(|ch| ch.is_ascii_digit())
            || token.len() != 4
            || !token
                .parse::<i64>()
                .ok()
                .is_some_and(|value| value > 1900 && value < 2050)
        {
            return;
        }
        if let Some(existing_year) = self.year.clone() {
            if self.en_name.as_deref().is_some_and(|name| !name.is_empty()) {
                append_with_space(&mut self.en_name, &existing_year);
            } else if self.cn_name.as_deref().is_some_and(|name| !name.is_empty()) {
                append_with_space(&mut self.cn_name, &existing_year);
            }
        } else if self
            .en_name
            .as_deref()
            .is_some_and(|name| ends_with_ignore_ascii(name, "SEASON"))
        {
            append_raw(&mut self.en_name, " ");
        }
        self.year = Some(token.to_string());
        self.last_token_type = "year".to_string();
        self.continue_flag = false;
        self.stop_name_flag = true;
    }

    /// 识别分辨率。
    fn parse_resource_pix(&mut self, token: &str) {
        if !self.has_name() {
            return;
        }
        if let Some(pix) = parse_resource_pix(token) {
            self.last_token_type = "pix".to_string();
            self.continue_flag = false;
            self.stop_name_flag = true;
            if self.resource_pix.is_none() {
                self.resource_pix = Some(pix);
            }
        }
    }

    /// 识别季信息并计算季总数。
    fn parse_season(&mut self, token: &str) {
        let seasons = capture_all_i64(&SEASON_RE, token);
        if !seasons.is_empty() {
            self.last_token_type = "season".to_string();
            self.media_type = Some("tv".to_string());
            self.stop_name_flag = true;
            self.continue_flag = true;
            for season in seasons {
                if self.begin_season.is_none() {
                    self.begin_season = Some(season);
                    self.total_season = 1;
                } else if Some(season) > self.begin_season {
                    self.end_season = Some(season);
                    self.total_season = season - self.begin_season.unwrap_or(season) + 1;
                    if self.isfile && self.total_season > 1 {
                        self.end_season = None;
                        self.total_season = 1;
                    }
                }
            }
            return;
        }
        if token.chars().all(|ch| ch.is_ascii_digit()) {
            if self.last_token_type == "SEASON" && self.begin_season.is_none() && token.len() < 3 {
                if let Ok(season) = token.parse::<i64>() {
                    self.begin_season = Some(season);
                    self.total_season = 1;
                    self.last_token_type = "season".to_string();
                    self.stop_name_flag = true;
                    self.continue_flag = false;
                    self.media_type = Some("tv".to_string());
                }
            }
        } else if token.eq_ignore_ascii_case("SEASON") && self.begin_season.is_none() {
            self.last_token_type = "SEASON".to_string();
        } else if self.media_type.as_deref() == Some("tv") && self.begin_season.is_none() {
            self.begin_season = Some(1);
        }
    }

    /// 识别集信息并计算集总数。
    fn parse_episode(&mut self, token: &str) {
        let episodes = capture_all_i64(&EPISODE_RE, token);
        if !episodes.is_empty() {
            self.last_token_type = "episode".to_string();
            self.continue_flag = false;
            self.stop_name_flag = true;
            self.media_type = Some("tv".to_string());
            for episode in episodes {
                if self.begin_episode.is_none() {
                    self.begin_episode = Some(episode);
                    self.total_episode = 1;
                } else if Some(episode) > self.begin_episode {
                    self.end_episode = Some(episode);
                    self.total_episode = episode - self.begin_episode.unwrap_or(episode) + 1;
                    if self.isfile && self.total_episode > 2 {
                        self.end_episode = None;
                        self.total_episode = 1;
                    }
                }
            }
            return;
        }
        if token.chars().all(|ch| ch.is_ascii_digit()) {
            let Ok(episode) = token.parse::<i64>() else {
                return;
            };
            if self.begin_episode.is_some()
                && self.end_episode.is_none()
                && token.len() < 5
                && Some(episode) > self.begin_episode
                && self.last_token_type == "episode"
            {
                self.end_episode = Some(episode);
                self.total_episode = episode - self.begin_episode.unwrap_or(episode) + 1;
                if self.isfile && self.total_episode > 2 {
                    self.end_episode = None;
                    self.total_episode = 1;
                }
                self.continue_flag = false;
                self.media_type = Some("tv".to_string());
            } else if self.begin_episode.is_none()
                && token.len() > 1
                && token.len() < 4
                && self.last_token_type != "year"
                && self.last_token_type != "videoencode"
                && token != self.unknown_name_str
            {
                self.begin_episode = Some(episode);
                self.total_episode = 1;
                self.last_token_type = "episode".to_string();
                self.continue_flag = false;
                self.stop_name_flag = true;
                self.media_type = Some("tv".to_string());
            } else if self.last_token_type == "EPISODE"
                && self.begin_episode.is_none()
                && token.len() < 5
            {
                self.begin_episode = Some(episode);
                self.total_episode = 1;
                self.last_token_type = "episode".to_string();
                self.continue_flag = false;
                self.stop_name_flag = true;
                self.media_type = Some("tv".to_string());
            }
        } else if token.eq_ignore_ascii_case("EPISODE") {
            self.last_token_type = "EPISODE".to_string();
        }
    }

    /// 识别片源和效果字段。
    fn parse_resource_type(&mut self, token: &str) {
        if !self.has_name() {
            return;
        }
        let upper = token.to_uppercase();
        if upper == "DL" && self.last_token_type == "source" && self.last_token == "WEB" {
            self.source = "WEB-DL".to_string();
            self.continue_flag = false;
            return;
        }
        if upper == "RAY" && self.last_token_type == "source" && self.last_token == "BLU" {
            self.source = if self.source == "UHD" {
                "UHD BluRay".to_string()
            } else {
                "BluRay".to_string()
            };
            self.continue_flag = false;
            return;
        }
        if upper == "WEBDL" {
            self.source = "WEB-DL".to_string();
            self.continue_flag = false;
            return;
        }
        if upper == "REMUX" && self.source == "BluRay" {
            self.source = "BluRay REMUX".to_string();
            self.continue_flag = false;
            return;
        }
        if upper == "BLURAY" && self.source == "UHD" {
            self.source = "UHD BluRay".to_string();
            self.continue_flag = false;
            return;
        }
        if SOURCE_RE.is_match(token) {
            self.last_token_type = "source".to_string();
            self.continue_flag = false;
            self.stop_name_flag = true;
            if self.source.is_empty() {
                self.source = normalize_source(token);
                self.last_token = self.source.to_uppercase();
            }
            return;
        }
        if EFFECT_RE.is_match(token) {
            self.last_token_type = "effect".to_string();
            self.continue_flag = false;
            self.stop_name_flag = true;
            if !self
                .effects
                .iter()
                .any(|effect| effect.eq_ignore_ascii_case(token))
            {
                self.effects.push(token.to_string());
            }
            self.last_token = upper;
        }
    }

    /// 识别常见流媒体平台简称。
    fn parse_streaming_platform(&mut self, token: &str) {
        if !self.has_name() {
            return;
        }
        let mut platform_name = streaming_platform_name(token);
        let mut query_range = 1usize;
        if platform_name.is_none() {
            let prev_token = if self.index >= 2 {
                self.tokens.get(self.index - 2)
            } else {
                None
            };
            let next_token = self.tokens.get(self.index);
            for (adjacent_token, is_next) in [(prev_token, false), (next_token, true)] {
                if adjacent_token.is_none() || platform_name.is_some() {
                    continue;
                }
                let adjacent_token = adjacent_token.unwrap();
                for separator in [" ", "-"] {
                    let combined = if is_next {
                        format!("{token}{separator}{adjacent_token}")
                    } else {
                        format!("{adjacent_token}{separator}{token}")
                    };
                    if let Some(name) = streaming_platform_name(&combined) {
                        platform_name = Some(name);
                        query_range = 2;
                        if is_next {
                            self.index += 1;
                        }
                        break;
                    }
                }
            }
        }
        let Some(platform_name) = platform_name else {
            return;
        };
        let match_start = self.index.saturating_sub(query_range + 1);
        let match_end = self.index.saturating_sub(1);
        let start = match_start.saturating_sub(query_range);
        let end = (match_end + 1 + query_range).min(self.tokens.len());
        if self.tokens[start..end].iter().any(|item| {
            matches!(
                item.to_uppercase().as_str(),
                "WEB" | "DL" | "WEBDL" | "WEBRIP"
            )
        }) {
            self.web_source = Some(platform_name.to_string());
            self.continue_flag = false;
        }
    }

    /// 识别视频编码。
    fn parse_video_encode(&mut self, token: &str) {
        if !self.has_name()
            || (self.year.is_none()
                && self.resource_pix.is_none()
                && self.source.is_empty()
                && self.begin_season.is_none()
                && self.begin_episode.is_none())
        {
            return;
        }
        if let Some(caps) = VIDEO_ENCODE_RE.captures(token) {
            self.continue_flag = false;
            self.stop_name_flag = true;
            self.last_token_type = "videoencode".to_string();
            if self.video_encode.is_none() {
                let encode = normalize_video_encode_capture(&caps);
                if let Some(encode) = encode {
                    self.last_token = encode.clone();
                    self.video_encode = Some(encode);
                }
            } else if self.video_encode.as_deref() == Some("10bit") {
                if let Some(encode) = normalize_video_encode_capture(&caps) {
                    self.video_encode = Some(format!("{encode} 10bit"));
                    self.last_token = encode;
                }
            }
            return;
        }
        let upper = token.to_uppercase();
        if upper == "H" || upper == "X" {
            self.continue_flag = false;
            self.stop_name_flag = true;
            self.last_token_type = "videoencode".to_string();
            self.last_token = if upper == "H" {
                upper
            } else {
                token.to_lowercase()
            };
        } else if matches!(token, "264" | "265")
            && self.last_token_type == "videoencode"
            && matches!(self.last_token.as_str(), "H" | "x")
        {
            self.video_encode = Some(format!("{}{}", self.last_token, token));
        } else if token.chars().all(|ch| ch.is_ascii_digit())
            && self.last_token_type == "videoencode"
            && matches!(self.last_token.as_str(), "VC" | "MPEG")
        {
            self.video_encode = Some(format!("{}{}", self.last_token, token));
        } else if upper == "10BIT" {
            self.last_token_type = "videoencode".to_string();
            if let Some(existing) = &mut self.video_encode {
                *existing = format!("{existing} 10bit");
            } else {
                self.video_encode = Some("10bit".to_string());
            }
        }
    }

    /// 识别视频位深字段。
    fn parse_video_bit(&mut self, token: &str) {
        if !self.has_name()
            || (self.year.is_none()
                && self.resource_pix.is_none()
                && self.source.is_empty()
                && self.begin_season.is_none()
                && self.begin_episode.is_none())
        {
            return;
        }
        let Some(video_bit) = parse_video_bit(token) else {
            return;
        };
        self.continue_flag = false;
        self.stop_name_flag = true;
        self.last_token_type = "videobit".to_string();
        if self.video_bit.is_none() {
            self.video_bit = Some(video_bit);
        }
    }

    /// 识别音频编码并合并 5.1、DTS-HD MA 等组合。
    fn parse_audio_encode(&mut self, token: &str) {
        if !self.has_name()
            || (self.year.is_none()
                && self.resource_pix.is_none()
                && self.source.is_empty()
                && self.begin_season.is_none()
                && self.begin_episode.is_none())
        {
            return;
        }
        if AUDIO_ENCODE_RE.is_match(token) {
            self.continue_flag = false;
            self.stop_name_flag = true;
            self.last_token_type = "audioencode".to_string();
            self.last_token = token.to_uppercase();
            if let Some(existing) = &mut self.audio_encode {
                if existing.eq_ignore_ascii_case("DTS") {
                    *existing = format!("{existing}-{token}");
                } else {
                    *existing = format!("{existing} {token}");
                }
            } else {
                self.audio_encode = Some(token.to_string());
            }
        } else if is_digit_token(token) && self.last_token_type == "audioencode" {
            if let Some(existing) = &mut self.audio_encode {
                if is_digit_token(&self.last_token) {
                    *existing = format!("{existing}.{token}");
                } else if existing
                    .chars()
                    .last()
                    .is_some_and(|ch| ch.is_ascii_digit())
                {
                    let split_at = existing.len() - 1;
                    *existing = format!(
                        "{} {}.{token}",
                        &existing[..split_at],
                        &existing[split_at..]
                    );
                } else {
                    *existing = format!("{existing} {token}");
                }
            }
            self.last_token = token.to_string();
        }
    }

    /// 识别 FPS 数值。
    fn parse_fps(&mut self, token: &str) {
        if !self.has_name() {
            return;
        }
        let Some(fps) = FPS_RE
            .captures(token)
            .and_then(|caps| caps.get(1))
            .and_then(|value| value.as_str().parse::<i64>().ok())
        else {
            return;
        };
        self.continue_flag = false;
        self.stop_name_flag = true;
        self.last_token_type = "fps".to_string();
        self.fps = Some(fps);
        self.last_token = format!("{fps}FPS");
    }

    /// 判断 token 是否是配置里的媒体后缀，防止文件扩展名进入标题。
    fn is_media_ext(&self, token: &str) -> bool {
        let suffix = format!(".{}", token.to_lowercase());
        self.media_exts.iter().any(|item| item == &suffix)
    }
}

/// 判断 token 是否全部为 Unicode 数字，兼容 Python str.isdigit 的行为。
fn is_digit_token(token: &str) -> bool {
    !token.is_empty() && token.chars().all(|ch| ch.is_numeric())
}
