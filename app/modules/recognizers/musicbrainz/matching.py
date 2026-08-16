"""MusicBrainz 候选匹配的文本处理与评分。

三件事：把资源标题与条目标题归一到可比对的形态（剥离音质规格、括号注释、卷号与
署名前缀，统一繁简与汉字数字）；据此构造 Recording 检索式；再按标题、艺术家、曲目数
与时长给候选打分并挑出可信目标。HTTP 通信与响应到领域对象的映射不在本模块。
"""
import re
from difflib import SequenceMatcher
from typing import Any, Iterable, Optional

from app.domain.context import MusicInfo
from app.domain.meta.metamusic import MetaMusic
from app.foundation.text import convert as zhconv_convert
from app.modules.recognizers.musicbrainz.api import MusicBrainzApi
from app.modules.recognizers.musicbrainz.mapping import (
    artist_credits,
    duration_seconds,
    optional_int,
)
from app.schemas.types import MediaSource

# 系列专辑的卷号后缀（好歌茹芸, Vol. 3）是发行分卷标记，条目本体不含卷号
_VOLUME_SUFFIX_RE = re.compile(r",?\s*vol\.?\s*\d+$", re.IGNORECASE)
# 卷号提取：标题任意位置的 Vol. N 写法，系列专辑弱匹配时用于分卷一致性校验
_VOLUME_NUMBER_RE = re.compile(r"vol\.?\s*(\d+)", re.IGNORECASE)
# 原声带资源标题的通用描述词尾部（条目本体是电影名）；
# 尾部描述词保留时作为原声带形态标记参与弱匹配判定
_SOUNDTRACK_SUFFIX_RE = re.compile(
    r"\s*(?:original\s+motion\s+picture|motion\s+picture)?\s*"
    r"(?<![A-Za-z0-9])(?:original\s+)?(?:soundtrack|score|ost)$",
    re.IGNORECASE,
)
# 演唱会资源的标题常带演出后缀（S.H.E十七音乐会），条目仅保留演出名本体
_PERFORMANCE_SUFFIX_RE = re.compile(
    r"\s*(?:音乐会|音樂會|演唱会|演唱會|巡回|巡演|Live|Tour)$", re.IGNORECASE)
# 常见汉字数字归一为阿拉伯数字：十三首/13首、二十周年/20周年 在条目与资源标题间混用
_CJK_DIGIT_MAP = {"零": 0, "一": 1, "二": 2, "两": 2, "三": 3, "四": 4,
                  "五": 5, "六": 6, "七": 7, "八": 8, "九": 9}
_CJK_NUMERAL_RUN_RE = re.compile(r"[零一二两三四五六七八九十百]+")
# 资源标题中的音质规格（格式、位深采样参数、年份后缀、发行实体标记）会污染检索式，检索前统一剥离
_QUALITY_TOKEN_RE = re.compile(
    r"\[[^\]]*\]|\((?:19|20)\d{2}\)|"
    r"\b(?:DSD(?:64|128|256|512)?|DSF|DFF|FLAC|ALAC|APE|WAV|WAVE|AIFF?|PCM|"
    r"MP3|AAC|M4A|OGG|VORBIS|OPUS|WMA|WEB-?DL|WEBRip|WEB)\b|"
    r"\b\d{1,3}\s*-?\s*bits?\b|\b\d{2,4}(?:\.\d)?\s*k(?:hz|bps?)\b|"
    # 流媒体发行实体标记（- Single / - EP），不是曲名的一部分
    r"\b(?:single|ep|album)\b",
    re.IGNORECASE,
)
# 专辑对位得分低于该阈值时宁可不匹配，避免把曲目写到错误的专辑上
ALBUM_MATCH_THRESHOLD = 60.0


def normalize_text(value: Optional[str]) -> str:
    """清理音乐检索文本中的多余空白，并统一繁简写法避免候选比对失误。

    :param value: 原始文本
    :return: 空白归一且转为简体的文本
    """
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return text
    # MusicBrainz 中文条目以简体为主，资源标题可能是繁体，比对前统一转简体
    try:
        return zhconv_convert(text, "zh-hans")
    except Exception:  # pylint: disable=broad-except
        return text


def match_text(value: Optional[str]) -> str:
    """移除大小写、空白、标点和繁简差异，生成相似度比较使用的紧凑文本。

    :param value: 原始文本
    :return: 只保留字母数字与汉字的紧凑简体文本
    """
    text = str(value or "").casefold()
    try:
        # 候选比对统一简体，避免条目繁体写法造成失配
        text = zhconv_convert(text, "zh-hans")
    except Exception:  # pylint: disable=broad-except
        pass
    return re.sub(r"[\W_]+", "", text, flags=re.UNICODE)


def convert_cjk_numerals(value: str) -> str:
    """将文本中连续的汉字数字转换为阿拉伯数字，支持十位与百位组合。

    :param value: 原始文本
    :return: 汉字数字段落替换为阿拉伯数字后的文本
    """

    def _convert(run: str) -> str:
        total, current = 0, 0
        for char in run:
            if char in _CJK_DIGIT_MAP:
                current = _CJK_DIGIT_MAP[char]
            elif char == "十":
                total += (current or 1) * 10
                current = 0
            elif char == "百":
                total += (current or 1) * 100
                current = 0
        return str(total + current)

    return _CJK_NUMERAL_RUN_RE.sub(lambda m: _convert(m.group()), str(value or ""))


def same_text(left: Optional[str], right: Optional[str]) -> bool:
    """忽略大小写、空白与标点差异比较两个音乐文本字段。

    :param left: 待比较文本
    :param right: 待比较文本
    :return: 两段文本是否指向同一内容
    """
    compact_left = match_text(left)
    compact_right = match_text(right)
    if compact_left and compact_left == compact_right:
        return True
    # 条目与资源标题的汉字数字写法不一致（十三首/13首），归一后再比对
    return bool(compact_left) and convert_cjk_numerals(
        compact_left) == convert_cjk_numerals(compact_right)


def text_similarity(left: Optional[str], right: Optional[str]) -> float:
    """忽略大小写和标点后比较两段音乐文本的相似度。

    :param left: 待比较文本
    :param right: 待比较文本
    :return: 0 到 1 之间的相似度，任一侧为空时为 0
    """
    normalized_left = match_text(left)
    normalized_right = match_text(right)
    if not normalized_left or not normalized_right:
        return 0.0
    return SequenceMatcher(None, normalized_left, normalized_right).ratio()


def unique_texts(values: Iterable[Optional[str]]) -> list[str]:
    """按规范化文本去重并保留原始顺序。

    :param values: 待去重的文本序列
    :return: 去重后的规范化文本列表
    """
    results: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = normalize_text(value)
        identity = normalized.casefold()
        if not normalized or identity in seen:
            continue
        seen.add(identity)
        results.append(normalized)
    return results


def search_title(value: Optional[str]) -> str:
    """剥离资源标题中的音频格式、规格参数与年份后缀，只保留曲名用于检索比对。

    :param value: 资源标题
    :return: 只含曲名的检索文本
    """
    text = _QUALITY_TOKEN_RE.sub(" ", str(value or ""))
    # 流媒体文件名消毒产生的下划线转空格，避免破坏检索短语
    text = text.replace("_", " ")
    # 规格剥离后可能残留悬空分隔符，统一修剪
    text = re.sub(r"^[\s\-–—/]+|[\s\-–—/]+$", "", normalize_text(text))
    # 格式标记后紧跟的场景发布组标签（如 ALAC-HHWEB），整体剔除
    text = re.sub(r"[-–—]\s*[A-Z0-9]{3,}\s*$", "", text)
    # 曲名尾部独立年份是发行线索不是曲名一部分（解析阶段通常已提取），
    # 反复剥离尾部年份：场景命名可能重复携带（Live At Montreux 2011 2011）
    text = normalize_text(text)
    while True:
        # 仅剔除空白分隔的尾部年份，纯年份标题（1999）无前导空白不受影响
        stripped = re.sub(r"\s+(?:19|20)\d{2}$", "", text)
        if stripped == text:
            break
        text = stripped
    return normalize_text(text)


def strip_parenthetical(value: str) -> str:
    """去除标题中的括号注释，保留主体曲名。

    :param value: 原始标题
    :return: 去掉括号注释后的标题
    """
    text = re.sub(r"[\(（][^\)）]*[\)）]", " ", str(value or ""))
    return normalize_text(text)


def main_title(value: Optional[str]) -> str:
    """提取冒号副标题结构的主标题，兼容全角/半角冒号。

    :param value: 原始标题
    :return: 冒号之前的主标题
    """
    text = re.split(r"\s*[：:]\s*", str(value or ""), maxsplit=1)[0]
    return normalize_text(text)


def head_title(value: Optional[str]) -> str:
    """提取候选「曲名-歌手」「曲名《巡演名》…」命名的首段曲名。

    :param value: 原始标题
    :return: 首个分隔符之前的曲名
    """
    text = re.split(r"\s*[-–—−－：:]\s*|\s*《", str(value or ""), maxsplit=1)[0]
    return normalize_text(text)


def lead_token(value: Optional[str]) -> str:
    """提取候选标题首个空白分隔段（「愛情電影主題曲 雲且留住」的主体名）。

    :param value: 原始标题
    :return: 首个空白分隔段；标题为空时返回空串
    """
    text = str(value or "").strip()
    return normalize_text(text.split(" ", 1)[0]) if text else ""


def strip_volume_suffix(value: Optional[str]) -> str:
    """剔除标题尾部的卷号后缀，返回专辑本体名。

    :param value: 原始标题
    :return: 去掉卷号后缀的专辑本体名
    """
    return normalize_text(_VOLUME_SUFFIX_RE.sub("", str(value or "")))


def volume_number(value: Optional[str]) -> Optional[str]:
    """提取标题中的卷号（Vol. 3 -> 3），无卷号返回 None。

    :param value: 原始标题
    :return: 卷号数字文本；无卷号时返回 None
    """
    match = _VOLUME_NUMBER_RE.search(str(value or ""))
    return match.group(1) if match else None


def soundtrack_body(value: Optional[str]) -> str:
    """剔除原声带标题尾部的通用描述词，返回电影名本体；无描述词返回空串。

    :param value: 原始标题
    :return: 电影名本体；标题不含原声带描述词时返回空串
    """
    text = str(value or "").strip()
    body = _SOUNDTRACK_SUFFIX_RE.sub("", text)
    if not body or body == text:
        return ""
    return normalize_text(body)


def performance_title(value: Optional[str]) -> str:
    """剔除标题尾部的演出形态后缀，返回演出名本体。

    :param value: 原始标题
    :return: 去掉演出形态后缀的演出名本体
    """
    return normalize_text(_PERFORMANCE_SUFFIX_RE.sub("", str(value or "")))


def strip_artist_prefix(title: Optional[str], artists: Optional[list[str]]) -> str:
    """剥离曲名开头的艺术家署名前缀（「许茹芸的爱情电影主题曲」）。

    资源命名习惯把署名放在曲名前，条目不含该前缀；署名身份由
    候选挑选阶段的艺术家要求保证，不会产生错误归属。前缀剥离后
    无剩余文本时保留原标题（「合集 - 花开」类短标题保护）。

    :param title: 原始曲名
    :param artists: 已知艺术家名称列表
    :return: 剥离署名前缀后的曲名
    """
    text = str(title or "").strip()
    for artist in artists or []:
        artist = str(artist or "").strip()
        if len(artist) < 2:
            continue
        if text.startswith(artist):
            remainder = re.sub(r"^[的之]\s*", "", text[len(artist):]).strip()
            if remainder:
                return remainder
    return text


def build_query(meta: MetaMusic) -> str:
    """构造 MusicBrainz Recording 搜索表达式。

    :param meta: 本地音频元数据
    :return: 由曲名、艺术家、专辑与 ISRC 组成的 AND 检索式
    """
    clauses = []
    # 资源标题先剥离音质标记，避免规格文本污染检索式导致零命中
    title = search_title(meta.title)
    if title:
        clauses.append(f"recording:{MusicBrainzApi.query_phrase(title)}")
    if meta.artists:
        clauses.append(f'artist:"{MusicBrainzApi.escape_query(meta.artists[0])}"')
    if meta.album:
        clauses.append(f'release:"{MusicBrainzApi.escape_query(meta.album)}"')
    if meta.isrc:
        clauses.append(f'isrc:"{MusicBrainzApi.escape_query(meta.isrc)}"')
    return " AND ".join(clauses)


def duration_similarity(left: int, right: int) -> float:
    """比较两个时长的接近程度，完全一致为 1，差异越大越接近 0。

    :param left: 时长秒数
    :param right: 时长秒数
    :return: 0 到 1 之间的接近程度
    """
    if not left or not right:
        return 0.0
    return max(0.0, 1 - abs(left - right) / max(left, right))


def release_track_summary(detail: dict[str, Any]) -> list[dict[str, Any]]:
    """提取发行版本的曲目概要（碟号、曲序、时长、标题）供打分使用。

    :param detail: Release 详情响应
    :return: 按介质与曲序展开的曲目概要列表
    """
    summary: list[dict[str, Any]] = []
    for medium in detail.get("media") or []:
        disc = optional_int(medium.get("position")) or 1
        for track in medium.get("tracks") or []:
            recording = track.get("recording") or {}
            summary.append({
                "disc": disc,
                "position": optional_int(track.get("position")),
                "length": duration_seconds(
                    track.get("length") or recording.get("length")
                ),
                "title": track.get("title") or recording.get("title"),
            })
    return summary


def score_release(
        meta: MetaMusic,
        tracks: list[MetaMusic],
        detail: dict[str, Any],
        summary: list[dict[str, Any]],
) -> float:
    """给候选发行版本打分（0-100），综合标题、歌手、曲目数和时长相似度。

    :param meta: 专辑目录线索
    :param tracks: 本地曲目元数据列表
    :param detail: Release 详情响应
    :param summary: 该发行版本的曲目概要
    :return: 0 到 100 的可信度得分
    """
    local_count = len(tracks)
    release_count = len(summary)
    if not release_count:
        return 0.0
    # 曲目数差异过大直接排除，避免单曲误命中整专或反之
    diff = abs(local_count - release_count)
    if diff > max(4, int(local_count * 0.5)):
        return 0.0
    # 本地文件比发行版本多出的曲目无法被覆盖，超出容忍范围视为错误候选
    if local_count > release_count and diff > max(1, int(release_count * 0.25)):
        return 0.0
    score = 0.0
    # 标题相似度：专辑目录名或文件标签中的专辑名/曲名
    title_hints = unique_texts([meta.album, meta.title])
    title_sim = max(
        (text_similarity(hint, detail.get("title")) for hint in title_hints),
        default=0.0,
    )
    artist_names = artist_credits(detail.get("artist-credit"))[0]
    if meta.artists and artist_names:
        artist_sim = max(
            text_similarity(meta.artists[0], name) for name in artist_names
        )
        score += 40 * title_sim + 15 * artist_sim
    else:
        # 缺少歌手线索时把权重让给标题
        score += 50 * title_sim
    # 曲目数：完全一致是最强信号
    if diff == 0:
        score += 15
    elif diff == 1:
        score += 8
    elif diff <= max(2, int(local_count * 0.15)):
        score += 2
    # 曲名重合度：部分曲目目录（只下载了整专的一部分）依靠曲名对位确认
    release_titles = {match_text(item["title"]) for item in summary}
    named_tracks = [track for track in tracks if track.title and not track.title.strip().isdigit()]
    if named_tracks and release_titles:
        overlap = sum(
            1 for track in named_tracks if match_text(track.title) in release_titles
        )
        score += 15 * overlap / len(named_tracks)
    # 总时长：无损整专 rip 的总时长与 MusicBrainz 记录高度接近
    local_total = sum(track.duration or 0 for track in tracks)
    release_total = sum(item["length"] or 0 for item in summary)
    local_durations = [track.duration for track in tracks if track.duration]
    if local_durations and release_total:
        delta = abs(local_total - release_total) / max(local_total, release_total)
        if delta <= 0.02:
            score += 15
        elif delta <= 0.05:
            score += 10
        elif delta <= 0.10:
            score += 5
    # 逐曲时长对位：曲目数一致时逐首比较
    if diff == 0 and len(local_durations) == local_count:
        similarities = []
        for track, item in zip(
            sorted(tracks, key=lambda item: (item.disc_number or 1, item.track_number or 0)),
            summary,
        ):
            if track.duration and item["length"]:
                similarities.append(duration_similarity(track.duration, item["length"]))
        if similarities:
            score += 15 * sum(similarities) / len(similarities)
    return score


def select_candidate(
        meta: MetaMusic,
        candidates: Iterable[MusicInfo],
        media_source: MediaSource,
) -> Optional[MusicInfo]:
    """按标题、艺术家和专辑匹配度选择最可信的搜索候选。

    :param meta: 本地音频元数据
    :param candidates: 搜索得到的候选列表
    :param media_source: 候选必须归属的数据源
    :return: 最可信的候选；无候选得分时返回 None
    """
    normalized_source = normalize_text(media_source).casefold()
    # 资源标题携带的音质标记先剥离，再与候选曲名比对；
    # 曲名开头的艺术家署名前缀是命名习惯，用主体名比对
    clean_title = strip_artist_prefix(search_title(meta.title), meta.artists)
    # 条目的影视 tie-in 注释多为全角括号，与资源半角注释无法精确相等，
    # 去括号后的主体曲名一致视为弱匹配，且需艺术家同时命中才采信；
    # 卷号后缀（Vol. 3）是发行分卷标记，条目本体不含卷号
    bare_title = strip_volume_suffix(strip_parenthetical(clean_title))
    ranked: list[tuple[int, MusicInfo]] = []
    for candidate in candidates:
        if normalized_source and str(candidate.media_source or "").casefold() != normalized_source:
            continue
        score = 0
        title_match = False
        # 多艺术家资源任一命中即可，联名候选不会因主艺术家顺序失配
        artist_match = bool(meta.artists) and any(
            same_text(artist_name, candidate_artist)
            for artist_name in meta.artists
            for candidate_artist in candidate.artists
        )
        if clean_title and same_text(clean_title, candidate.title):
            score += 4
            title_match = True
        elif (
            bare_title
            and artist_match
            and (
                same_text(bare_title, strip_parenthetical(candidate.title))
                # 条目「天國的情人：鄧麗君逝世十周年…」这类冒号副标题，主标题一致视为弱匹配
                or same_text(bare_title, main_title(candidate.title))
                # 条目「为你盛开-许巍《无尽光芒》…」这类连字符前置命名，首段曲名一致视为弱匹配
                or same_text(bare_title, head_title(candidate.title))
                # 条目「愛情電影主題曲 雲且留住」这类「主体名 补充说明」结构，首段一致视为弱匹配
                or (
                    len(match_text(bare_title)) >= 3
                    and same_text(bare_title, lead_token(candidate.title))
                )
                # 条目带额外前缀/后缀完整包含资源主体名（好莱坞原声带类），长文本包含视为弱匹配
                or (
                    len(match_text(bare_title)) >= 6
                    and match_text(bare_title) in match_text(candidate.title)
                )
                # 资源标题带演出后缀（S.H.E十七音乐会），条目本体一致视为弱匹配
                or (
                    performance_title(bare_title)
                    and same_text(performance_title(bare_title), candidate.title)
                )
            )
        ):
            score += 2
            title_match = True
        if artist_match:
            score += 3
        if meta.album and same_text(meta.album, candidate.album):
            score += 2
        isrc_match = bool(meta.isrc) and same_text(meta.isrc, candidate.isrc)
        if isrc_match:
            score += 5
        # 同名多版本（如不同年份的重发单曲）靠发行年份消歧
        if meta.year and candidate.year and int(meta.year) == int(candidate.year):
            score += 1
        # 已知艺术家时，艺术家未命中的候选不能采信（ISRC 精确身份除外），
        # 兜住宽检索阶梯下同名异曲的误配；CJK 逐字 OR 检索召回宽，
        # 标题未命中的候选同样不能仅凭艺术家署名得分（ISRC 除外）
        if (meta.artists and not artist_match and not isrc_match) or (
            not title_match and not isrc_match
        ):
            score = 0
        ranked.append((score, candidate))
    if not ranked:
        return None
    ranked.sort(key=lambda item: item[0], reverse=True)
    return ranked[0][1] if ranked[0][0] > 0 else None


def select_album_candidate(meta: MetaMusic, albums: Iterable[MusicInfo]) -> Optional[MusicInfo]:
    """单曲检索未命中时，从专辑候选中挑选高置信目标。

    专辑重名多，要求标题（含去括号弱匹配）与艺术家同时命中才返回，
    避免把音轨身份安到错误专辑上。

    :param meta: 本地音频元数据
    :param albums: 专辑候选列表
    :return: 最可信的专辑候选；无候选得分时返回 None
    """
    clean_title = strip_artist_prefix(
        search_title(meta.album or meta.title), meta.artists)
    if not clean_title:
        return None
    # 去括号与卷号后缀后的本体名用于弱匹配（好歌茹芸, Vol. 3 -> 好歌茹芸）；
    # 资源带卷号时弱匹配要求候选卷号一致，避免 Ibiza Vol.1 误配 Vol.3
    bare_title = strip_volume_suffix(strip_parenthetical(clean_title))
    meta_volume = volume_number(clean_title)
    ranked: list[tuple[int, MusicInfo]] = []
    for album in albums:
        score = 0
        album_title = album.title or album.album
        artist_match = bool(meta.artists) and any(
            same_text(artist_name, candidate_artist)
            for artist_name in meta.artists
            for candidate_artist in album.artists
        )
        title_match = False
        # 资源带卷号时候选卷号不一致（含其他分卷）直接排除，避免 Vol.1 误配 Vol.3
        if meta_volume and volume_number(album_title) not in (None, meta_volume):
            pass
        elif same_text(clean_title, album_title):
            score += 4
            title_match = True
        elif (
            artist_match
            and bare_title
            and (
                same_text(bare_title, strip_parenthetical(album_title))
                # 条目「天國的情人：鄧麗君逝世十周年…」这类冒号副标题，主标题一致视为弱匹配
                or same_text(bare_title, main_title(album_title))
                # 条目「为你盛开-许巍《无尽光芒》…」这类连字符前置命名，首段曲名一致视为弱匹配
                or same_text(bare_title, head_title(album_title))
                # 条目「愛情電影主題曲 雲且留住」这类「主体名 补充说明」结构，首段一致视为弱匹配
                or (
                    len(match_text(bare_title)) >= 3
                    and same_text(bare_title, lead_token(album_title))
                )
                # 条目带额外前缀/后缀完整包含资源主体名（好莱坞原声带类），长文本包含视为弱匹配
                or (
                    len(match_text(bare_title)) >= 6
                    and match_text(bare_title) in match_text(album_title)
                )
                # 资源标题带演出后缀（S.H.E十七音乐会），条目本体一致视为弱匹配
                or (
                    performance_title(bare_title)
                    and same_text(performance_title(bare_title), album_title)
                )
                # 原声带资源的描述词在条目中常省略（Pulp Fiction: Music From the…），
                # 电影名本体与条目标题或主标题一致视为弱匹配
                or (
                    len(match_text(soundtrack_body(bare_title))) >= 4
                    and (
                        same_text(soundtrack_body(bare_title), album_title)
                        or same_text(soundtrack_body(bare_title), main_title(album_title))
                    )
                )
            )
        ):
            # 「我爱夜 (新歌+精选)」对位条目「我爱夜」这类注释差异
            score += 2
            title_match = True
        if artist_match:
            score += 3
        if meta.year and album.year and int(meta.year) == int(album.year):
            score += 1
        # 标题与艺术家缺一不可，仅有标题相似不能采信
        ranked.append((score if title_match and artist_match else 0, album))
    if not ranked:
        return None
    ranked.sort(key=lambda item: item[0], reverse=True)
    return ranked[0][1] if ranked[0][0] > 0 else None


def interleave_results(*groups: list[MusicInfo], limit: int) -> list[MusicInfo]:
    """按实体轮询合并结果，避免单曲数量占满全局搜索页。

    :param groups: 按实体分组的候选列表
    :param limit: 返回条数上限
    :return: 各组轮流取一条合并后的候选列表
    """
    results: list[MusicInfo] = []
    index = 0
    while len(results) < limit and any(index < len(group) for group in groups):
        for group in groups:
            if index < len(group):
                results.append(group[index])
                if len(results) >= limit:
                    break
        index += 1
    return results
