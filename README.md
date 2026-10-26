# Project 3 - Subnetting and Forwarding

- Name: Anthony Baird
- Email: anthonybaird@u.boisestate.edu
- Class: 425-001

## Known Bugs or Issues

None

## Experience

I tried GPT 6 Luna for this one, since it was a simpler project and Luna is much cheaper; just to see if I would run into more problems, since Claude has fairly consistently 1-shotted everything in the past. I've been using Luna A LOT on a side-project, and in my experience it almost never gets the code right on the first try unless it's incredibly easy, and it does not always have the cleanest design. As far as functionality, it does pretty well if testing is in place for it to ram against a couple of times, which did happen a couple of times in this project. If the next project isn't too hard either, perhaps I'll let my local Qwen3.6 35B model give it a shot!

I glanced through everything that it was doing before acceptance, let it figure out how to pass the tests, manually checked that it was adding the desired test cases described in the assignment, and let it handle coverage for me in a more automated way this time (all coverage at once, rather than case by case). I double-checked that it didn't add any extra gcovr excludes with grep. Then I switched to Claude and had it review the project as well to find errors (custom test suite?). It did not find any.

Finally, I had Luna create a gh codespace environment and test the code there as well as on onyx, reading the commands it was running before acceptance. No issues.

To double-check all functionality faster afterwards, I had Luna give me a markdown report of all functions' inputs, outputs, and descriptions of edge cases and implementations.

## Design

IPv4 addresses have the first octet at the left end. The parsers accept four decimal octets and a valid CIDR prefix, and reject extra text, out-of-range values, and ambiguous leading zeroes.

Subnet math uses a mask to separate the network from the host part. 
 - A `/0`'s mask is all zeroes; its `2^32` addresses are counted in a 64-bit value so the number fits. 
 - `/31` has exactly two addresses. Both are usable on a point-to-point link:
   the network address is the first host, the broadcast address is the last
   host, and the host count is 2.
 - `/32` contains exactly the address written before `/32`. 

For a lookup, the table checks every route that contains the destination and keeps the longest prefix. A default `/0` route is the fallback when no more-specific route matches. 
