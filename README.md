# retired htb machines

my personal collection of writeups and study notes for retired hack the box machines. everything in here is either a box past its retirement date, a starting point machine, tier 0 academy content, or one of the five mini pro labs htb lets you publish freely (poo, xen, ascension, rpg, hades). nothing active, nothing exclusive, nothing that breaks htb's terms of service, checked every single time before anything gets committed.

## why this exists

i do these boxes to actually learn, not just to pop a shell and move on. so instead of letting the knowledge evaporate the second i grab root, i break every box down into proper notes: what tool did what, why a specific flag mattered, why the vulnerability worked the way it did, not just "ran this, got that." future me (or anyone else poking around a similar box) should be able to open a writeup here and actually rebuild the reasoning, not just copy commands.

## structure

each machine gets its own md:

```
README.md
kobold/
another-retired-machine-name/
...
```

## what a writeup actually contains

- a quick 80/20 summary up top, read that if you're short on time
- the actual walkthrough, command by command, with the why behind each flag, not just the what
- a breakdown table of every tool/technique used and what it solved
- real sources: cve records, github pocs, writeups i cross referenced, nothing invented
- a short "security angle" on the root cause, how it'd get abused and how it'd get defended against in a real environment, not just "box solved"

## rules i stick to

- retired machines only, retired is not the same as expired, expired just means the box stopped counting for seasonal points, it can still be unpublishable

## disclaimer

everything here is for educational purposes. all content covers retired or officially free to publish htb material, per htb's own terms of service. this repo is not affiliated with hack the box, it's just my own study trail.