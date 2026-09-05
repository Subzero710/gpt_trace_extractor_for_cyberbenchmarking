#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path.cwd()


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.exists():
        raise SystemExit(f"[p2p-fix] missing expected file: {rel}")
    return path.read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    (ROOT / rel).write_text(text, encoding="utf-8")
    print(f"[p2p-fix] updated {rel}")


def replace_once(text: str, old: str, new: str, *, rel: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"[p2p-fix] {rel}: expected exactly one {label}, found {count}; refusing to guess"
        )
    return text.replace(old, new, 1)


def insert_after_once(text: str, marker: str, addition: str, *, rel: str, label: str) -> str:
    return replace_once(text, marker, marker + addition, rel=rel, label=label)


def patch_p2p_services() -> None:
    rel = "ledger/p2p_services.py"
    text = read(rel)

    if "class P2PPriceChanged" not in text:
        text = insert_after_once(
            text,
            """class P2PNoAgentAvailable(ValidationError):
    pass


""",
            """class P2PPriceChanged(ValidationError):
    pass


""",
            rel=rel,
            label="P2PNoAgentAvailable class",
        )

    text = replace_once(
        text,
        """    base_qs = P2PMakerProfile.objects.filter(
        status=P2PMakerProfile.STATUS_ACTIVE,
        accepting_orders=True,
    )
""",
        """    base_qs = P2PMakerProfile.objects.filter(
        status=P2PMakerProfile.STATUS_ACTIVE,
        accepting_orders=True,
    ).exclude(
        telegram_user_id="",
        discord_user_id="",
    )
""",
        rel=rel,
        label="P2P catalog base queryset",
    )

    text = replace_once(
        text,
        """        .filter(_method_filter(payment_method))
        .exclude(user=buyer)
        .exclude(pk__in=tuple(excluded_ids))
""",
        """        .filter(_method_filter(payment_method))
        .exclude(user=buyer)
        .exclude(telegram_user_id="", discord_user_id="")
        .exclude(pk__in=tuple(excluded_ids))
""",
        rel=rel,
        label="P2P pool notification identity filter",
    )

    text = replace_once(
        text,
        """        try:
            from .p2p_tasks import expire_p2p_agent_offer
            from .tasks import notify_admin_event

            # MediaCMS emits a generic event to n8n. n8n owns the Telegram /
            # Discord credentials and is responsible for the actual notification.
            notify_admin_event.delay("p2p.agent_offer", payload, event_id)
            expire_p2p_agent_offer.apply_async(args=[assignment_id], countdown=timeout)
""",
        """        try:
            from .p2p_tasks import expire_p2p_agent_offer, notify_p2p_agent_offer

            # MediaCMS only emits the P2P offer event. n8n owns the Telegram /
            # Discord credentials and is responsible for the actual notification.
            notify_p2p_agent_offer.delay(payload, event_id)
            expire_p2p_agent_offer.apply_async(args=[assignment_id], countdown=timeout)
""",
        rel=rel,
        label="P2P assignment notification dispatch",
    )

    text = replace_once(
        text,
        """@transaction.atomic
def create_p2p_order_for_checkout(*, buyer, token_pack: TokenPack, payment_method: str) -> P2POrder:
""",
        """@transaction.atomic
def create_p2p_order_for_checkout(
    *,
    buyer,
    token_pack: TokenPack,
    payment_method: str,
    expected_transaction_amount: int | None = None,
) -> P2POrder:
""",
        rel=rel,
        label="P2P order creation signature",
    )

    price_block = """    commission_percent, commission_amount, transaction_amount = _price_for_maker(
        base_amount=base_amount,
        maker=maker,
    )
    order = P2POrder.objects.create(
"""
    guarded_price_block = """    commission_percent, commission_amount, transaction_amount = _price_for_maker(
        base_amount=base_amount,
        maker=maker,
    )
    if expected_transaction_amount is not None:
        try:
            expected_amount = int(expected_transaction_amount)
        except (TypeError, ValueError) as exc:
            raise ValidationError("Invalid expected P2P transaction value") from exc
        if expected_amount <= 0:
            raise ValidationError("Invalid expected P2P transaction value")
        if expected_amount != int(transaction_amount):
            raise P2PPriceChanged(
                "P2P transaction value changed. Please review the updated price."
            )

    order = P2POrder.objects.create(
"""
    if guarded_price_block not in text:
        text = replace_once(
            text,
            price_block,
            guarded_price_block,
            rel=rel,
            label="P2P checkout price guard",
        )

    write(rel, text)


def patch_p2p_tasks() -> None:
    rel = "ledger/p2p_tasks.py"
    text = read(rel)

    if "def notify_p2p_agent_offer" in text:
        return

    text = replace_once(
        text,
        """from __future__ import annotations

from celery import shared_task
""",
        """from __future__ import annotations

import logging

import requests
from celery import shared_task
from django.conf import settings


logger = logging.getLogger(__name__)
""",
        rel=rel,
        label="P2P task imports",
    )

    notification_task = '''

@shared_task(
    bind=True,
    name="ledger.notify_p2p_agent_offer",
    queue="short_tasks",
    autoretry_for=(requests.RequestException,),
    retry_backoff=True,
    retry_backoff_max=60,
    retry_jitter=True,
    retry_kwargs={"max_retries": 3},
)
def notify_p2p_agent_offer(self, payload, event_id=""):
    """Deliver a P2P offer event to the dedicated n8n workflow.

    MediaCMS never talks to Telegram/Discord directly. n8n owns those credentials.
    """
    if getattr(settings, "TESTING", False):
        return False

    webhook_url = str(getattr(settings, "P2P_N8N_WEBHOOK_URL", "") or "").strip()
    webhook_secret = str(
        getattr(settings, "P2P_N8N_WEBHOOK_SECRET", "") or ""
    ).strip()
    if not webhook_url or not webhook_secret:
        logger.warning(
            "P2P n8n webhook is not fully configured; skipping agent offer event"
        )
        return False

    body = dict(payload or {})
    body["event"] = "p2p.agent_offer"
    body["event_id"] = str(event_id or "")

    response = requests.post(
        webhook_url,
        json=body,
        headers={
            "Content-Type": "application/json",
            "X-P2P-Webhook-Secret": webhook_secret,
            "X-P2P-Event-ID": str(event_id or ""),
        },
        timeout=5.0,
    )
    response.raise_for_status()
    return True
'''
    text = insert_after_once(
        text,
        "logger = logging.getLogger(__name__)\n",
        notification_task,
        rel=rel,
        label="P2P logger",
    )
    write(rel, text)


def patch_p2p_bot_views() -> None:
    rel = "ledger/p2p_bot_views.py"
    text = read(rel)

    text = text.replace("import os\n", "")

    old = """def _configured_n8n_action_secret() -> str:
    configured = str(getattr(settings, "P2P_N8N_ACTION_SECRET", "") or "").strip()
    if configured:
        return configured
    return str(os.environ.get("NOTIFICATION_WEBHOOK_SECRET", "") or "").strip()


def _supplied_n8n_action_secret(request) -> str:
    return str(
        request.headers.get("X-P2P-Action-Secret")
        or request.headers.get("X-Notification-Secret")
        or ""
    ).strip()
"""
    new = """def _configured_n8n_action_secret() -> str:
    return str(getattr(settings, "P2P_N8N_ACTION_SECRET", "") or "").strip()


def _supplied_n8n_action_secret(request) -> str:
    return str(request.headers.get("X-P2P-Action-Secret") or "").strip()
"""
    if old in text:
        text = text.replace(old, new, 1)
    elif "NOTIFICATION_WEBHOOK_SECRET" in text or "X-Notification-Secret" in text:
        raise SystemExit(
            "[p2p-fix] ledger/p2p_bot_views.py: unexpected legacy notification-secret shape"
        )

    write(rel, text)


def patch_settings() -> None:
    rel = "cms/settings.py"
    text = read(rel)

    old = """P2P_N8N_ACTION_SECRET = os.environ.get(
    "P2P_N8N_ACTION_SECRET",
    os.environ.get("NOTIFICATION_WEBHOOK_SECRET", ""),
).strip()
"""
    new = """P2P_N8N_WEBHOOK_URL = os.environ.get("P2P_N8N_WEBHOOK_URL", "").strip()
P2P_N8N_WEBHOOK_SECRET = os.environ.get("P2P_N8N_WEBHOOK_SECRET", "").strip()
P2P_N8N_ACTION_SECRET = os.environ.get("P2P_N8N_ACTION_SECRET", "").strip()
"""
    if old in text:
        text = text.replace(old, new, 1)
    elif "P2P_N8N_WEBHOOK_URL" not in text:
        raise SystemExit("[p2p-fix] cms/settings.py: could not locate P2P n8n settings")

    write(rel, text)


def patch_wallet_template() -> None:
    rel = "templates/cms/wallet.html"
    text = read(rel)

    marker = """      <input type="hidden" name="deposit_option_key" value="" data-wallet-selected-route>
"""
    addition = """      <input type="hidden" name="p2p_expected_transaction_amount" value="" data-wallet-p2p-expected-transaction-amount>
"""
    if "data-wallet-p2p-expected-transaction-amount" not in text:
        text = insert_after_once(
            text,
            marker,
            addition,
            rel=rel,
            label="selected route input",
        )

    write(rel, text)


def patch_wallet_js() -> None:
    rel = "frontend/src/static/js/pages/wallet-buy-flow.js"
    text = read(rel)

    if "function setP2PExpectedTransactionAmount" not in text:
        marker = """  function getP2PPreviewUrl() {
    const form = getBuyForm();
    return form ? (form.getAttribute('data-p2p-preview-url') || '') : '';
  }

"""
        addition = """  function setP2PExpectedTransactionAmount(value) {
    const form = getBuyForm();
    const input = form
      ? form.querySelector('[data-wallet-p2p-expected-transaction-amount]')
      : null;
    if (!input) {
      return;
    }
    const amount = Number(value || 0);
    input.value = Number.isFinite(amount) && amount > 0 ? String(Math.trunc(amount)) : '';
  }

"""
        text = insert_after_once(
            text,
            marker,
            addition,
            rel=rel,
            label="P2P preview URL helper",
        )

    p2p_start = text.find("requestP2PPrice(routes[0]).then(function (result)")
    if p2p_start < 0:
        raise SystemExit("[p2p-fix] wallet JS: missing single-route P2P submit block")
    p2p_end = text.find("            });", p2p_start)
    segment = text[p2p_start:p2p_end]
    if "setP2PExpectedTransactionAmount(result.transactionAmount);" not in segment:
        old = """              syncBuyFormTarget();
              form.submit();
"""
        new = """              setP2PExpectedTransactionAmount(result.transactionAmount);
              syncBuyFormTarget();
              form.submit();
"""
        if old not in segment:
            raise SystemExit("[p2p-fix] wallet JS: missing P2P form.submit block")
        segment = segment.replace(old, new, 1)
        text = text[:p2p_start] + segment + text[p2p_end:]

    old_listener = """  const buyForm = getBuyForm();
  if (buyForm) {
    buyForm.addEventListener('submit', function () {
      syncBuyFormTarget();
      if (buyState.paymentOpenNewTab) {
        window.setTimeout(function () {
          closeModal('deposit');
        }, 0);
      }
    });
  }
"""
    new_listener = """  const buyForm = getBuyForm();
  if (buyForm) {
    buyForm.addEventListener('submit', function (event) {
      const route = getRouteByKey(buyState.routeKey);
      if (route && route.paymentPriceMode === 'p2p_dynamic') {
        const cacheKey = getP2PPriceCacheKey(route);
        const cached = p2pPriceCache.get(cacheKey);
        if (!cached || !cached.available || !cached.transactionAmount) {
          event.preventDefault();
          requestP2PPrice(route).then(function (result) {
            if (!result.available || !result.transactionAmount) {
              renderStep4Choices();
              return;
            }
            setP2PExpectedTransactionAmount(result.transactionAmount);
            buyForm.requestSubmit();
          });
          return;
        }
        setP2PExpectedTransactionAmount(cached.transactionAmount);
      } else {
        setP2PExpectedTransactionAmount(0);
      }

      syncBuyFormTarget();
      if (buyState.paymentOpenNewTab) {
        window.setTimeout(function () {
          closeModal('deposit');
        }, 0);
      }
    });
  }
"""
    if old_listener in text:
        text = text.replace(old_listener, new_listener, 1)
    elif "buyForm.addEventListener('submit', function (event)" not in text:
        raise SystemExit("[p2p-fix] wallet JS: unexpected submit-listener shape")

    write(rel, text)


def patch_wallet_view() -> None:
    rel = "files/views.py"
    text = read(rel)

    old = """        if (
            selected_option.get("payment_method_type") == "provider"
            and selected_option.get("provider_key") == P2P_PROVIDER_KEY
        ):
            order = create_p2p_order_for_checkout(
                buyer=request.user,
                token_pack=token_pack,
                payment_method=selected_option.get("p2p_payment_method") or "",
            )
            return redirect("p2p_exchange", public_id=order.public_id)
"""
    new = """        if (
            selected_option.get("payment_method_type") == "provider"
            and selected_option.get("provider_key") == P2P_PROVIDER_KEY
        ):
            expected_amount_raw = (
                request.POST.get("p2p_expected_transaction_amount") or ""
            ).strip()
            try:
                expected_transaction_amount = int(expected_amount_raw)
            except (TypeError, ValueError) as exc:
                raise DjangoValidationError(
                    "Please review the current P2P transaction value and try again."
                ) from exc
            if expected_transaction_amount <= 0:
                raise DjangoValidationError(
                    "Please review the current P2P transaction value and try again."
                )

            order = create_p2p_order_for_checkout(
                buyer=request.user,
                token_pack=token_pack,
                payment_method=selected_option.get("p2p_payment_method") or "",
                expected_transaction_amount=expected_transaction_amount,
            )
            return redirect("p2p_exchange", public_id=order.public_id)
"""
    if old in text:
        text = text.replace(old, new, 1)
    elif "p2p_expected_transaction_amount" not in text:
        raise SystemExit("[p2p-fix] files/views.py: could not locate P2P checkout branch")

    write(rel, text)


def patch_compose(rel: str) -> None:
    text = read(rel)

    web_pos = text.find("  web:")
    celery_pos = text.find("  celery_worker:")
    if web_pos < 0 or celery_pos < 0:
        raise SystemExit(f"[p2p-fix] {rel}: missing web/celery_worker service")

    web_section = text[web_pos:celery_pos]
    if "P2P_N8N_ACTION_SECRET:" not in web_section:
        web_anchor = """      AI_GENERATION_N8N_WAKE_WEBHOOK_URL: ${AI_GENERATION_N8N_WAKE_WEBHOOK_URL}
      AI_GENERATION_N8N_WAKE_SECRET: ${AI_GENERATION_N8N_WAKE_SECRET}
"""
        if web_anchor not in web_section:
            raise SystemExit(f"[p2p-fix] {rel}: missing web n8n anchor")
        web_section = web_section.replace(
            web_anchor,
            web_anchor + "      P2P_N8N_ACTION_SECRET: ${P2P_N8N_ACTION_SECRET}\n",
            1,
        )
        text = text[:web_pos] + web_section + text[celery_pos:]
        celery_pos = text.find("  celery_worker:")

    next_service = text.find("\n  db:", celery_pos)
    if next_service < 0:
        raise SystemExit(f"[p2p-fix] {rel}: could not delimit celery_worker")
    celery_section = text[celery_pos:next_service]
    if "P2P_N8N_WEBHOOK_URL:" not in celery_section:
        generic_anchor = """      NOTIFICATION_WEBHOOK_URL: ${NOTIFICATION_WEBHOOK_URL}
      NOTIFICATION_WEBHOOK_SECRET: ${NOTIFICATION_WEBHOOK_SECRET}
"""
        p2p_values = """      P2P_N8N_WEBHOOK_URL: ${P2P_N8N_WEBHOOK_URL}
      P2P_N8N_WEBHOOK_SECRET: ${P2P_N8N_WEBHOOK_SECRET}
"""
        if generic_anchor in celery_section:
            celery_section = celery_section.replace(
                generic_anchor, generic_anchor + p2p_values, 1
            )
        else:
            ai_anchor = """      AI_GENERATION_N8N_WAKE_WEBHOOK_URL: ${AI_GENERATION_N8N_WAKE_WEBHOOK_URL}
      AI_GENERATION_N8N_WAKE_SECRET: ${AI_GENERATION_N8N_WAKE_SECRET}
"""
            if ai_anchor not in celery_section:
                raise SystemExit(f"[p2p-fix] {rel}: missing celery n8n anchor")
            celery_section = celery_section.replace(
                ai_anchor, ai_anchor + p2p_values, 1
            )
        text = text[:celery_pos] + celery_section + text[next_service:]

    write(rel, text)


def patch_tests() -> None:
    rel = "tests/ledger/test_p2p_transaction_flow.py"
    text = read(rel)

    if "from django.core.exceptions import ValidationError" not in text:
        text = replace_once(
            text,
            "from django.contrib.auth.models import Permission\n",
            "from django.contrib.auth.models import Permission\nfrom django.core.exceptions import ValidationError\n",
            rel=rel,
            label="ValidationError test import",
        )

    old_import = """from ledger.p2p_services import (
    create_p2p_order_for_checkout,
    find_new_p2p_agent,
    mark_p2p_fiat_received,
    mark_p2p_fiat_sent,
    respond_to_p2p_agent_offer,
)
"""
    new_import = """from ledger.p2p_services import (
    P2PNoAgentAvailable,
    create_p2p_order_for_checkout,
    find_new_p2p_agent,
    mark_p2p_fiat_received,
    mark_p2p_fiat_sent,
    preview_p2p_checkout,
    respond_to_p2p_agent_offer,
)
"""
    if old_import in text:
        text = text.replace(old_import, new_import, 1)

    if "test_price_change_between_preview_and_submit_requires_reconfirmation" not in text:
        addition = '''
    def test_price_change_between_preview_and_submit_requires_reconfirmation(self):
        preview = preview_p2p_checkout(
            buyer=self.customer,
            token_pack=self.pack,
            payment_method=P2POrder.PAYMENT_METHOD_CARD,
        )
        self.assertEqual(preview["transaction_amount"], 52_000_000)

        self.agent_a.accepting_orders = False
        self.agent_a.save(update_fields=["accepting_orders", "updated_at"])

        with self.assertRaisesMessage(
            ValidationError,
            "P2P transaction value changed. Please review the updated price.",
        ):
            create_p2p_order_for_checkout(
                buyer=self.customer,
                token_pack=self.pack,
                payment_method=P2POrder.PAYMENT_METHOD_CARD,
                expected_transaction_amount=preview["transaction_amount"],
            )
        self.assertEqual(P2POrder.objects.count(), 0)

    def test_agents_without_notification_identity_are_not_selectable(self):
        P2PMakerProfile.objects.update(
            telegram_user_id="",
            discord_user_id="",
        )
        with self.assertRaises(P2PNoAgentAvailable):
            preview_p2p_checkout(
                buyer=self.customer,
                token_pack=self.pack,
                payment_method=P2POrder.PAYMENT_METHOD_CARD,
            )

'''
        insert_at = text.rfind("    def test_offered_agent_cannot_access_chat_until_acceptance")
        if insert_at < 0:
            raise SystemExit(f"[p2p-fix] {rel}: test insertion point not found")
        text = text[:insert_at] + addition + text[insert_at:]

    write(rel, text)

    rel = "tests/ledger/test_p2p_bot_identity.py"
    text = read(rel)

    if "import json\n" not in text:
        text = text.replace("\nfrom decimal import Decimal\n", "\nimport json\nfrom decimal import Decimal\n", 1)
    if "from django.test import TestCase, override_settings" not in text:
        text = text.replace(
            "from django.test import TestCase\n",
            "from django.test import TestCase, override_settings\n",
            1,
        )

    if "test_n8n_callback_requires_dedicated_p2p_action_secret" not in text:
        addition = '''

    @override_settings(P2P_N8N_ACTION_SECRET="dedicated-p2p-secret")
    def test_n8n_callback_requires_dedicated_p2p_action_secret(self):
        users = get_user_model()
        buyer = users.objects.create_user(username="p2p_n8n_buyer")
        agent_user = users.objects.create_user(username="p2p_n8n_agent")
        maker = P2PMakerProfile.objects.create(
            user=agent_user,
            status=P2PMakerProfile.STATUS_ACTIVE,
            accepting_orders=True,
            card_enabled=True,
            telegram_user_id="456",
            commission_percent=Decimal("1.00"),
        )
        order = P2POrder.objects.create(
            buyer=buyer,
            maker=maker,
            payment_method=P2POrder.PAYMENT_METHOD_CARD,
            platform_amount=10_100_000,
            status=P2POrder.STATUS_WAITING_AGENT,
        )
        assignment = P2PAgentAssignment.objects.create(
            order=order,
            maker=maker,
            expires_at=order.created_at + __import__("datetime").timedelta(minutes=5),
            transaction_amount_snapshot=order.platform_amount,
        )
        body = json.dumps(
            {
                "action_token": str(assignment.action_token),
                "action": "decline",
                "channel": "telegram",
                "external_user_id": "456",
            }
        )

        legacy = self.client.post(
            "/api/p2p/n8n/agent-response",
            data=body,
            content_type="application/json",
            HTTP_X_NOTIFICATION_SECRET="dedicated-p2p-secret",
        )
        self.assertEqual(legacy.status_code, 403)

        response = self.client.post(
            "/api/p2p/n8n/agent-response",
            data=body,
            content_type="application/json",
            HTTP_X_P2P_ACTION_SECRET="dedicated-p2p-secret",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["state"], "declined")
'''
        text = text.rstrip() + addition + "\n"

    write(rel, text)


def sanity_checks() -> None:
    bot = read("ledger/p2p_bot_views.py")
    services = read("ledger/p2p_services.py")
    tasks = read("ledger/p2p_tasks.py")
    settings = read("cms/settings.py")

    if "NOTIFICATION_WEBHOOK_SECRET" in bot or "X-Notification-Secret" in bot:
        raise SystemExit("[p2p-fix] legacy generic notification secret still used by P2P callback")
    if "notify_admin_event" in services:
        raise SystemExit("[p2p-fix] P2P still dispatches through the generic admin notification workflow")
    for key in (
        "P2P_N8N_WEBHOOK_URL",
        "P2P_N8N_WEBHOOK_SECRET",
        "P2P_N8N_ACTION_SECRET",
    ):
        if key not in settings:
            raise SystemExit(f"[p2p-fix] missing setting {key}")
    if "X-P2P-Webhook-Secret" not in tasks:
        raise SystemExit("[p2p-fix] dedicated P2P webhook auth header missing")


def main() -> int:
    patch_p2p_services()
    patch_p2p_tasks()
    patch_p2p_bot_views()
    patch_settings()
    patch_wallet_template()
    patch_wallet_js()
    patch_wallet_view()

    for rel in (
        "docker-compose-dev.yaml",
        "docker-compose.yaml",
        "docker-compose-cloudflare.yaml",
    ):
        patch_compose(rel)

    patch_tests()
    sanity_checks()

    print("[p2p-fix] done")
    print("[p2p-fix] no migration files were created or modified")
    print("[p2p-fix] dedicated env vars:")
    print("  P2P_N8N_WEBHOOK_URL")
    print("  P2P_N8N_WEBHOOK_SECRET")
    print("  P2P_N8N_ACTION_SECRET")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
