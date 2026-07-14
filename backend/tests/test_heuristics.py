from app.detection.heuristics import FLAG_THRESHOLD, score_email


def test_clean_email_is_not_flagged() -> None:
    result = score_email(
        sender_domain="newsletter.example.com",
        subject="Your weekly digest",
        links=["https://example.com/digest/42"],
        body="Here's what happened this week in your neighborhood.",
    )
    assert not result.flagged
    assert result.score < FLAG_THRESHOLD
    assert result.rationale == "No phishing indicators detected."


def test_ip_literal_link_is_flagged() -> None:
    result = score_email(
        sender_domain="example.com",
        subject="Invoice attached",
        links=["http://192.168.1.50/login"],
        body="Please review the attached invoice.",
    )
    assert result.flagged
    assert any("raw IP address" in signal for signal in result.signals)


def test_punycode_link_is_flagged() -> None:
    result = score_email(
        sender_domain="example.com",
        subject="Account notice",
        links=["https://xn--pypal-4ve.com/login"],
        body="Please review your account.",
    )
    assert result.flagged
    assert any("punycode" in signal for signal in result.signals)


def test_brand_impersonation_link_is_flagged() -> None:
    result = score_email(
        sender_domain="secure-alerts.com",
        subject="Unusual activity on your account",
        links=["https://paypal-secure-login.com/verify"],
        body="We noticed unusual activity, please verify your account immediately.",
    )
    assert result.flagged
    assert any("paypal" in signal for signal in result.signals)


def test_legit_brand_domain_is_not_flagged_as_impersonation() -> None:
    result = score_email(
        sender_domain="paypal.com",
        subject="Your monthly statement",
        links=["https://www.paypal.com/statements/march"],
        body="Your statement is ready to view.",
    )
    assert not result.flagged
    assert not any("impersonat" in signal.lower() or "references" in signal for signal in result.signals)


def test_free_webmail_claiming_to_be_a_bank_is_flagged() -> None:
    result = score_email(
        sender_domain="gmail.com",
        subject="Chase account alert: unusual activity detected",
        links=["https://chase-alerts.com/verify"],
        body="Dear customer, please confirm your identity immediately or your account will be closed.",
    )
    assert result.flagged
    assert any("free webmail domain" in signal for signal in result.signals)


def test_urgency_language_alone_is_scored_but_may_not_flag() -> None:
    result = score_email(
        sender_domain="example.com",
        subject="Act now: limited time offer",
        links=["https://example.com/offer"],
        body="Act now for this limited time offer before it's gone!",
    )
    assert result.score > 1
    assert any("Urgency" in signal for signal in result.signals)


def test_generic_greeting_with_sensitive_request_is_scored() -> None:
    result = score_email(
        sender_domain="example.com",
        subject="Account verification needed",
        links=["https://example.com/verify"],
        body="Dear customer, please provide your social security number to verify your account.",
    )
    assert any("sensitive personal" in signal for signal in result.signals)


def test_url_shortener_contributes_but_is_not_solely_determinative() -> None:
    result = score_email(
        sender_domain="example.com",
        subject="Check this out",
        links=["https://bit.ly/3xample"],
        body="Take a look at this link.",
    )
    assert any("URL shortener" in signal for signal in result.signals)
    assert result.score < FLAG_THRESHOLD


def test_suspicious_tld_contributes() -> None:
    result = score_email(
        sender_domain="example.com",
        subject="Special offer",
        links=["https://free-prize.top/claim"],
        body="You have won a special offer, act now to claim your prize.",
    )
    assert result.flagged
    assert any("abused for phishing" in signal for signal in result.signals)


def test_malformed_link_does_not_crash_and_is_noted() -> None:
    result = score_email(
        sender_domain="example.com",
        subject="Broken link test",
        links=["not a real url ::::"],
        body="This has a malformed link.",
    )
    assert any("Malformed link" in signal for signal in result.signals)


def test_score_is_capped_between_one_and_ten() -> None:
    result = score_email(
        sender_domain="gmail.com",
        subject="URGENT: Chase account suspended, verify your account immediately",
        links=[
            "http://192.168.1.1/chase-login",
            "https://xn--chse-mra.top/verify",
            "https://paypal-secure-login.com/confirm",
            "https://bit.ly/scam",
        ],
        body=(
            "Dear customer, your account will be closed. Confirm your identity, "
            "provide your social security number and credit card number now. "
            "Act now, this is an urgent action required, click here immediately."
        ),
    )
    assert 1 <= result.score <= 10
    assert result.score == 10
    assert result.flagged
