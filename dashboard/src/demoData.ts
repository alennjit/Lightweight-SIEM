import type { Alert } from "./types";

/*
 * Sample alerts for the public demo build (`npm run build:demo`), which is
 * hosted on GitHub Pages with no backend behind it. The messages are
 * fictional, but each score and rationale is the real output of
 * backend/app/detection/heuristics.py for that message — keep it that way
 * if you add samples (run them through score_email and paste the result).
 */

function minutesAgo(minutes: number): string {
  return new Date(Date.now() - minutes * 60_000).toISOString();
}

export function demoAlerts(): Alert[] {
  return [
    {
      id: 5,
      sender_domain: "gmail.com",
      subject: "Chase account alert: unusual activity detected",
      links: ["http://chase-secure-login.top/verify"],
      score: 10,
      rationale:
        "Sender uses a free webmail domain (gmail.com) but message claims to be from chase; " +
        "Link domain (chase-secure-login.top) references 'chase' but is not chase.com; " +
        "Link uses a TLD commonly abused for phishing (.top); " +
        "Urgency/credential-harvesting language detected: verify your account, unusual activity",
      created_at: minutesAgo(4),
    },
    {
      id: 4,
      sender_domain: "usps-redelivery.info",
      subject: "Your package could not be delivered - action required",
      links: ["https://bit.ly/3usps-fee", "http://192.0.2.44/redeliver"],
      score: 10,
      rationale:
        "Sender domain (usps-redelivery.info) references 'usps' but is not usps.com; " +
        "Link uses a URL shortener (bit.ly), which hides the real destination; " +
        "Link points to a raw IP address (192.0.2.44) instead of a domain",
      created_at: minutesAgo(95),
    },
    {
      id: 3,
      sender_domain: "outlook.com",
      subject: "Microsoft 365: your password expires today",
      links: ["https://xn--microsft-login-7ib.com/keep-password"],
      score: 9,
      rationale:
        "Sender uses a free webmail domain (outlook.com) but message claims to be from microsoft; " +
        "Link domain uses punycode encoding (xn--microsft-login-7ib.com), often used to spoof lookalike domains; " +
        "Urgency/credential-harvesting language detected: confirm your password",
      created_at: minutesAgo(60 * 26),
    },
    {
      id: 2,
      sender_domain: "amazon-orders-support.com",
      subject: "Your order #112-4471 has been cancelled",
      links: ["https://amazon-orders-support.com/refund"],
      score: 9,
      rationale:
        "Sender domain (amazon-orders-support.com) references 'amazon' but is not amazon.com; " +
        "Link domain (amazon-orders-support.com) references 'amazon' but is not amazon.com",
      created_at: minutesAgo(60 * 50),
    },
    {
      id: 1,
      sender_domain: "support-ticket-center.com",
      subject: "Dear customer, your account needs attention",
      links: ["http://203.0.113.9/login"],
      score: 5,
      rationale: "Link points to a raw IP address (203.0.113.9) instead of a domain",
      created_at: minutesAgo(60 * 24 * 4),
    },
  ];
}
