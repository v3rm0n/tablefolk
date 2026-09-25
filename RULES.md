# Sasku — Rules

## Overview

Sasku is a trick-taking game for **4 players in fixed partnerships**. The player sitting
opposite you is your partner; every trick your side wins belongs to both of you.

Each player is dealt **9 cards**.

The deck has **36 cards**: 6, 7, 8, 9, 10, Jack, Queen, King, and Ace in each
of clubs, spades, hearts, and diamonds.

## Card point values

| Card | Points |
|---|---|
| Ace | 11 |
| Ten | 10 |
| King | 4 |
| Queen | 3 |
| Jack | 2 |

All other cards are worth nothing.

## Trumps and card ranking

**All court cards (King, Queen, Jack of every suit) are permanent trumps.** Kings beat all queens, and queens beat all jacks. Within each rank, suits run from strongest to weakest: **clubs → spades → hearts → diamonds**.

High to low, the courts run:

> K♣ K♠ K♥ K♦ · Q♣ Q♠ Q♥ Q♦ · J♣ J♠ J♥ J♦

So the **King of clubs** is the strongest court card — and the strongest card in the game.
The **Jack of diamonds** is the weakest court card.

The **Ace is not a court card**. It ranks between the Ten and the Jack: above the Ten,
below every court card.

In addition to the twelve courts, the remaining cards of the **chosen trump suit** are
trumps. They rank below all court cards.

Within a non-court suit, cards rank **A > 10 > 9 > 8 > 7 > 6**. This order also
applies to the non-court cards of the chosen trump suit, below the twelve courts.

## Bidding

The trump suit is decided by bidding before play.

To work out your bid:

1. Count the **court cards** in your hand.
2. Add the number of **non-court cards** you hold in your longest suit.

Court cards are excluded from the suit count, so each court counts only once.

- Bidding starts with the player after the dealer and proceeds cyclically in
  seat order **1 → 2 → 3 → 4**.
- On your turn, pass or bid your **exact calculated hand strength**, provided
  it strictly exceeds the current highest bid. Equal bids cannot replace it.
- Passing does not eliminate you: you may bid on a later turn if bidding continues.
- Three consecutive passes after a bid end the auction. The **highest bidder
  then names the trump suit**.
- There is no reason to outbid your own partner — you play on the same side.
- **On your bidding turn, you may instead name diamonds immediately**, without
  making a numerical overbid. This ends bidding, and you are the trump declarer.
- Four passes before any bid end bidding as a **pass-round**, with diamonds
  becoming trump automatically and no declarer.

## Playing a trick

**Courts count only as trumps, not as their printed suits, when following.**

- If a plain suit is led and you hold a non-court card of that suit, you must
  play one of those cards.
- If any trump is led, you must play a trump if you hold one. All courts and
  all remaining cards of the chosen trump suit belong to this effective suit.
- If you cannot follow the effective led suit, **any card is allowed**. You are
  not required to trump, and there is no obligation to beat the current winner.

For example, when diamonds are trump and hearts are led, holding only the queen
of hearts does not mean you can follow hearts: that queen is a trump. You may
play it or discard another card.

The strongest trump played wins the trick. If no trump is played, the strongest
card of the led plain suit wins; an off-suit discard cannot win.

The trump declarer leads the first trick. In a pass-round, the player after the
dealer leads. Play follows the same cyclic seat order as bidding, and each
trick's winner leads the next trick. After the ninth trick, score the hand and
advance the dealer one seat. Initial dealer selection and match termination are
still to be specified.

## Scoring

### Card points

At the end of the hand, each partnership adds up the card points in the tricks it has
taken. There are **120 card points** in the deck, so **61 points wins the hand**.

### Game points

The winning partnership then scores game points, depending on how many card points it
took and on **who named the trump suit**.

**Simple win — 61 to 89 card points (*lihtvõit*)**

| Trump suit | Winners named trump | Opponents named trump |
|---|---|---|
| Any named suit | 2 P | 4 P |
| Diamonds | 4 P | 6 P |

**Bonuses**

| Result | Bonus |
|---|---|
| Exactly 90 card points (*seajänn*, "pig jänn") | +1 P |
| 91 card points or more (*jänn*) | +2 P |

### Special results

- **Karvane** ("hairy") — one partnership takes **no tricks at all**. The winning side
  scores **12 P**, regardless of the trump suit.
- **Pokk** — the hand ends **60 : 60**. The partnership that did **not** name the trump
  suit scores **2 P**.
- **Üleküla ruutu** ("diamonds round the village") — the pass-round hand, where nobody
  bids and diamonds becomes trump by default. The partnership with more card points
  scores **2 P**. No bonus is added for *jänn* or *karvane*, and a *pokk* in
  *üleküla ruutu* scores nothing for either side.
