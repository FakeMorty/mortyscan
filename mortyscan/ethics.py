"""Этический «шлюз». Пользователь обязан явно подтвердить полномочия,
прежде чем запускать активные/разрушительные проверки."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

console = Console()


@dataclass
class Authorization:
    target: str
    owner_or_authorized: bool = False
    allow_intrusive: bool = False        # активные пробы (фуззинг, SQLi/XSS)
    allow_stress: bool = False           # стресс-тест (нагрузка)
    allow_local_arp: bool = False        # ARP-скан локальной сети
    operator: Optional[str] = None
    purpose: Optional[str] = None

    def summary(self) -> dict:
        return {
            "цель":                       self.target,
            "владелец_или_авторизован":   self.owner_or_authorized,
            "разрешён_активный_скан":     self.allow_intrusive,
            "разрешён_стресс_тест":       self.allow_stress,
            "разрешён_arp_скан":          self.allow_local_arp,
            "оператор":                   self.operator,
            "цель_сканирования":          self.purpose,
        }


WARNING = """[bold red]ЮРИДИЧЕСКОЕ И ЭТИЧЕСКОЕ ПРЕДУПРЕЖДЕНИЕ[/bold red]

MortyScan умеет проводить [bold]активное тестирование[/bold]
(подбор путей, инъекции, сканирование портов) и
[bold red]нагрузочный (DoS-подобный) тест[/bold red] против указанной цели.

Запуск этих функций против систем, которыми вы [bold]НЕ владеете[/bold]
и на тестирование которых у вас [bold]НЕТ письменного разрешения[/bold],
является [bold]уголовно наказуемым деянием[/bold] в большинстве стран:
  • РФ — статьи 272, 273 и 274 УК РФ
  • США — Computer Fraud and Abuse Act (CFAA)
  • Великобритания — Computer Misuse Act 1990
  • ЕС — Директива 2013/40/EU
  • и аналогичные законы в других юрисдикциях.

Продолжая, вы подтверждаете, что:
  • вы являетесь владельцем цели,  ЛИБО
  • у вас есть явное письменное разрешение её тестировать
    (договор на пентест, in-scope актив bug bounty, лабораторный стенд).

Вы принимаете на себя [bold]полную юридическую и этическую ответственность[/bold]
за все действия, совершённые с помощью этого инструмента.
Автор предоставляет программу «КАК ЕСТЬ», без гарантий,
исключительно в образовательных целях и для авторизованного аудита."""


def interactive_gate(target: str, want_intrusive: bool = True,
                     want_stress: bool = False, want_arp: bool = False,
                     assume_yes: bool = False) -> Authorization:
    auth = Authorization(target=target)
    console.print(Panel(WARNING, border_style="red", title="MortyScan v18 «Инквизитор»"))

    if assume_yes:
        auth.owner_or_authorized = True
        auth.allow_intrusive = want_intrusive
        auth.allow_stress = want_stress
        auth.allow_local_arp = want_arp
        auth.operator = "yes-флаг (CI)"
        auth.purpose = "запуск с --yes"
        return auth

    auth.owner_or_authorized = Confirm.ask(
        f"[bold]Подтверждаю, что у меня есть право тестировать «{target}»[/bold]",
        default=False,
    )
    if not auth.owner_or_authorized:
        console.print("[red]Подтверждение не получено. Останавливаюсь.[/red]")
        raise SystemExit(2)

    auth.operator = Prompt.ask("Ваше имя или ник (для журнала аудита)", default="anon")
    auth.purpose = Prompt.ask("Цель сканирования", default="плановый аудит")

    if want_intrusive:
        auth.allow_intrusive = Confirm.ask(
            "Разрешить [yellow]АКТИВНЫЕ[/yellow] проверки "
            "(подбор путей, проверки на SQLi/XSS/LFI/SSRF)?",
            default=True,
        )
    if want_stress:
        console.print(
            "[bold red]ВНИМАНИЕ:[/bold red] стресс-тест отправляет лавину запросов "
            "и может замедлить или уронить сайт."
        )
        auth.allow_stress = Confirm.ask(
            "Я понимаю риски и всё равно хочу запустить [red]стресс-тест[/red]?",
            default=False,
        )
    if want_arp:
        auth.allow_local_arp = Confirm.ask(
            "Разрешить ARP-сканирование ВАШЕЙ локальной сети?", default=False,
        )
    return auth
