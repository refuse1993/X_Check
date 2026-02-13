"""
GPT 기반 위협 인텔리전스 분석기
- 수집된 트윗에서 한국 금융회사 관련 내용 필터링
- 관련 내용 있으면 요약해서 Mattermost 발송
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

import requests

# 설정
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
MATTERMOST_WEBHOOK = os.getenv("MATTERMOST_WEBHOOK")
DATA_DIR = Path(os.getenv("DATA_DIR", "data"))
TARGETS = os.getenv("TARGETS", "").split(",")

# 한국 금융회사 키워드 (GPT 프롬프트에서 참조용)
KOREAN_FINANCIAL_KEYWORDS = """
- 은행: 국민은행, 신한은행, 하나은행, 우리은행, 농협, NH, IBK기업은행, SC제일은행, 케이뱅크, 카카오뱅크, 토스뱅크
- 증권: 삼성증권, 미래에셋, 한국투자증권, NH투자증권, KB증권, 키움증권, 대신증권
- 보험: 삼성생명, 삼성화재, 현대해상, DB손해보험, 한화생명, 교보생명, 메리츠화재
- 카드: 삼성카드, 신한카드, 현대카드, 롯데카드, 하나카드, 우리카드, BC카드
- 핀테크: 카카오페이, 네이버페이, 토스, 페이코, 쿠팡페이
- 기관: 금융감독원, 금융위원회, 한국은행, 예금보험공사, 금융결제원, 코스콤
- 거래소: 업비트, 빗썸, 코인원, 코빗
- 일반: 한국, Korea, KR, .kr, Korean bank, Korean financial
"""


def load_latest_tweets() -> list[dict]:
    """config의 타겟별 최신 수집 파일에서 트윗 로드"""
    all_tweets = []

    for target in TARGETS:
        target = target.strip()
        if not target:
            continue

        target_dir = DATA_DIR / target
        if not target_dir.exists():
            continue

        # 최신 파일 찾기
        json_files = sorted(target_dir.glob("*.json"), reverse=True)
        if not json_files:
            continue

        latest_file = json_files[0]
        try:
            with open(latest_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                tweets = data.get("tweets", [])
                for tweet in tweets:
                    tweet["_keyword"] = target  # 어떤 키워드로 수집됐는지 표시
                all_tweets.extend(tweets)
        except Exception as e:
            print(f"파일 로드 실패 {latest_file}: {e}")

    return all_tweets


def analyze_with_gpt(tweets: list[dict]) -> dict:
    """GPT로 한국 금융회사 관련 트윗 분석"""

    if not tweets:
        return {"relevant": False, "summary": "", "details": []}

    # 트윗 텍스트 준비
    tweet_texts = []
    for i, tweet in enumerate(tweets[:30]):  # 최대 30개만 분석 (비용 절약)
        text = tweet.get("text", "")
        user = tweet.get("user", {}).get("username", "unknown")
        date = tweet.get("date", "")
        link = tweet.get("link", "")
        keyword = tweet.get("_keyword", "")
        tweet_texts.append(f"[{i+1}] @{user} ({date}) [키워드: {keyword}]\n{text}\n링크: {link}")

    tweets_content = "\n---\n".join(tweet_texts)

    prompt = f"""당신은 사이버 위협 인텔리전스 및 금융 서비스 모니터링 분석가입니다.

아래 트윗들을 분석하여 **한국 금융회사/금융기관**과 관련된 다음 상황이 있는지 판단하세요:
1. 사이버 공격 (DDoS, 랜섬웨어, 데이터 유출 등)
2. 서비스 장애 (앱 오류, 접속 불가, 결제 장애, 송금 안됨 등)
3. 보안 사고 (해킹, 정보 유출 등)

## 중요 판단 기준:
- 트윗에서 한국 금융회사/서비스가 **직접 언급**되거나 **명확히 추론 가능**해야 함
- 단순히 "결제 안됨"만 있고 어떤 서비스인지 불명확하면 제외
- 게임 결제, 해외 서비스, 쇼핑몰 자체 오류 등은 제외
- **여러 사람이 동시에 같은 금융사 문제를 언급**하면 실제 장애 가능성 높음

## 한국 금융 관련 키워드 참고:
{KOREAN_FINANCIAL_KEYWORDS}

## 분석할 트윗들:
{tweets_content}

## 응답 형식 (JSON):
{{
    "relevant": true/false,  // 한국 금융회사 관련 이슈가 있으면 true
    "confidence": "high/medium/low",  // 확신도
    "issue_type": "cyber_attack/service_outage/security_incident/none",
    "summary": "한국어로 2-3문장 요약 (관련 없으면 빈 문자열)",
    "details": [
        {{
            "tweet_index": 1,
            "company": "관련 회사/기관명 (예: 카카오뱅크, 토스, 신한카드)",
            "issue_type": "이슈 유형 (DDoS, 앱장애, 결제오류, 데이터유출 등)",
            "severity": "high/medium/low",
            "summary": "해당 트윗 요약"
        }}
    ]
}}

한국 금융회사와 직접적인 관련이 없거나 불명확하면 relevant: false로 응답하세요.
반드시 유효한 JSON만 출력하세요.
"""

    try:
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity threat analyst. Respond only in valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.3,
                "max_tokens": 2000
            },
            timeout=60
        )

        if response.status_code != 200:
            print(f"OpenAI API 오류: {response.status_code} - {response.text}")
            return {"relevant": False, "summary": "", "details": []}

        result = response.json()
        content = result["choices"][0]["message"]["content"]

        # JSON 파싱 (```json 블록 제거)
        content = content.strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[1]
        if content.endswith("```"):
            content = content.rsplit("```", 1)[0]

        return json.loads(content.strip())

    except Exception as e:
        print(f"GPT 분석 오류: {e}")
        return {"relevant": False, "summary": "", "details": []}


def send_mattermost(analysis: dict, tweets: list[dict]) -> bool:
    """분석 결과를 Mattermost로 발송"""

    if not MATTERMOST_WEBHOOK:
        print("MATTERMOST_WEBHOOK 미설정")
        return False

    now = datetime.now().strftime("%Y-%m-%d %H:%M KST")

    # 메시지 구성
    message = f"""### 🚨 한국 금융권 위협 감지

| 항목 | 내용 |
|------|------|
| 탐지 시간 | {now} |
| 확신도 | {analysis.get('confidence', 'N/A')} |

#### 📋 요약
{analysis.get('summary', 'N/A')}

"""

    # 상세 내용 추가
    details = analysis.get("details", [])
    if details:
        message += "#### 🔍 상세 내용\n\n"
        for detail in details[:5]:  # 최대 5개
            idx = detail.get("tweet_index", 0)
            if idx > 0 and idx <= len(tweets):
                tweet = tweets[idx - 1]
                link = tweet.get("link", "#")
                message += f"""**{detail.get('company', 'N/A')}** - {detail.get('threat_type', 'N/A')} ({detail.get('severity', 'N/A')})
> {detail.get('summary', '')}
> [원본 보기]({link})

"""

    message += f"\n---\n[GitHub Issues](https://github.com/{os.getenv('GITHUB_REPOSITORY', '')}/issues)"

    try:
        response = requests.post(
            MATTERMOST_WEBHOOK,
            json={"text": message},
            headers={"Content-Type": "application/json"},
            timeout=30
        )

        if response.status_code in [200, 201]:
            print("Mattermost 발송 성공")
            return True
        else:
            print(f"Mattermost 발송 실패: {response.status_code} - {response.text}")
            return False

    except Exception as e:
        print(f"Mattermost 발송 오류: {e}")
        return False


def main():
    print("=" * 50)
    print("GPT 기반 위협 인텔리전스 분석 시작")
    print("=" * 50)

    # API 키 확인
    if not OPENAI_API_KEY:
        print("❌ OPENAI_API_KEY 미설정 - 분석 스킵")
        sys.exit(0)

    # 트윗 로드
    tweets = load_latest_tweets()
    print(f"📥 로드된 트윗: {len(tweets)}건")

    if not tweets:
        print("분석할 트윗 없음")
        sys.exit(0)

    # GPT 분석
    print("🤖 GPT 분석 중...")
    analysis = analyze_with_gpt(tweets)

    print(f"📊 분석 결과: relevant={analysis.get('relevant')}, confidence={analysis.get('confidence')}")

    # 관련 있으면 Mattermost 발송
    if analysis.get("relevant"):
        print("🚨 한국 금융권 관련 위협 감지!")
        print(f"   요약: {analysis.get('summary')}")

        if MATTERMOST_WEBHOOK:
            send_mattermost(analysis, tweets)
        else:
            print("⚠️ MATTERMOST_WEBHOOK 미설정 - 발송 스킵")
    else:
        print("✅ 한국 금융권 관련 위협 없음 - 발송 스킵")

    # 결과 저장 (로그용)
    result_file = DATA_DIR / f"_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(result_file, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "tweet_count": len(tweets),
            "analysis": analysis
        }, f, ensure_ascii=False, indent=2)
    print(f"📁 분석 결과 저장: {result_file}")


if __name__ == "__main__":
    main()
