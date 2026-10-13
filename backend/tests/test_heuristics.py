import pytest

from app.detection.heuristics import (
    CATEGORY_DANGEROUS_LINK,
    CATEGORY_IMPERSONATION,
    CATEGORY_SCAM_REQUEST,
    CATEGORY_SUSPICIOUS_SENDER,
    FLAG_THRESHOLD,
    score_email,
)


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


# --- Scam-pattern rules and categories -------------------------------------

@pytest.mark.parametrize(
    ("sender", "subject", "body"),
    [
        (
            "parish-office-news.com",
            "Quick favor - are you available?",
            "Hi, I need you to pick up a gift card for me today. Reply as soon as possible, I will pay you back.",
        ),
        (
            "gmail.com",
            "Are you free?",
            "I'm in a meeting and can't talk. I need you to buy 4 Google Play cards of $100 each and "
            "send me the codes. Keep this between us.",
        ),
    ],
)
def test_gift_card_scam_is_flagged(sender: str, subject: str, body: str) -> None:
    result = score_email(sender_domain=sender, subject=subject, links=[], body=body)
    assert result.flagged
    assert CATEGORY_SCAM_REQUEST in result.categories


@pytest.mark.parametrize(
    ("sender", "subject", "body"),
    [
        ("target.com", "Holiday gift cards are here", "Give the perfect gift. Buy a Target gift card in any amount."),
        ("gmail.com", "Thanks for the birthday gift card!", "Grandma, thank you so much for the gift card! I used it to buy books."),
    ],
)
def test_ordinary_gift_card_mail_is_not_flagged(sender: str, subject: str, body: str) -> None:
    result = score_email(sender_domain=sender, subject=subject, links=[], body=body)
    assert not result.flagged
    assert CATEGORY_SCAM_REQUEST not in result.categories


def test_fake_renewal_callback_scam_is_flagged() -> None:
    result = score_email(
        sender_domain="gmail.com",
        subject="Norton 360 auto-renewal invoice #88213",
        links=[],
        body="Your subscription has been renewed for $349.99. If you did not authorize this, "
        "call our billing desk at (888) 555-0142 to cancel.",
    )
    assert result.flagged
    assert result.categories == [CATEGORY_IMPERSONATION, CATEGORY_SCAM_REQUEST]
    assert any("phone number" in s and "dollar amount" in s for s in result.signals)


def test_geek_squad_lookalike_sender_is_flagged() -> None:
    result = score_email(
        sender_domain="geeksquad-billing.com",
        subject="Your Geek Squad renewal of $399.99 has been processed",
        links=[],
        body="If you did not authorize this charge call us immediately to cancel and receive a refund.",
    )
    assert result.score >= 8
    assert CATEGORY_SCAM_REQUEST in result.categories


@pytest.mark.parametrize(
    ("sender", "subject", "body"),
    [
        ("bestbuy.com", "Your order confirmation",
         "Thanks for your order! To cancel or change it, visit your account. Questions? Call us at 1-888-237-8289."),
        ("comcast.net", "Your bill is ready",
         "Your Xfinity invoice is ready. Payment of $89.99 will be charged on 11/02 via autopay."),
        ("amazon.com", "Your refund has been processed",
         "We've issued a refund of $24.99 to your original payment method."),
    ],
)
def test_ordinary_receipts_and_bills_are_not_flagged(sender: str, subject: str, body: str) -> None:
    result = score_email(sender_domain=sender, subject=subject, links=[], body=body)
    assert not result.flagged


def test_suspicious_sender_tld_contributes() -> None:
    result = score_email(
        sender_domain="rewards-center.top",
        subject="You've been selected for a $500 grocery reward",
        links=["https://bit.ly/claim-500-reward"],
        body="Claim your reward before it expires.",
    )
    assert result.flagged
    assert result.categories == [CATEGORY_SUSPICIOUS_SENDER, CATEGORY_DANGEROUS_LINK]


@pytest.mark.parametrize("domain", ["googlegroups.com", "firstbank.com", "startups.com"])
def test_short_brand_names_inside_ordinary_words_are_not_impersonation(domain: str) -> None:
    result = score_email(sender_domain=domain, subject="Weekly update", links=[], body="Here is the news.")
    assert not result.flagged


@pytest.mark.parametrize("domain", ["irs-refund-portal.com", "ups-tracking.info"])
def test_short_brand_names_as_whole_tokens_are_still_impersonation(domain: str) -> None:
    result = score_email(sender_domain=domain, subject="Weekly update", links=[], body="Here is the news.")
    assert result.flagged
    assert result.categories == [CATEGORY_IMPERSONATION]


def test_clean_email_has_no_categories() -> None:
    result = score_email(sender_domain="example.com", subject="Hello", links=[], body="See you Sunday.")
    assert result.categories == []
