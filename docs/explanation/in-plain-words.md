# What this is for, in plain words

This page is for anyone curious about what wtcat does, with no background in networking or security needed.

## A ticket, checked at the door

A Common Access Token, or CAT, works like a ticket to a show. Whoever sells access, the box office, writes the
ticket and signs it in a way nobody else can copy. Whoever serves the content, the door, checks the signature and
the terms on the ticket before letting anyone in. The terms can say things like "good until 9 o'clock", "only for
this show", "only for this person's device", or "only in this country". If the ticket was changed, has run out, or
is being used somewhere it wasn't meant for, the door says no.

wtcat is the door. It is a library that a server uses to check tickets and say yes or no, and why.

## Where you've met this already

You have almost certainly used tokens like this without seeing them.

- **Streaming video.** When you watch a show or a live game online, the video doesn't come as one big file. It
  arrives in small pieces, a few seconds each, usually from a server near you run by a content delivery network,
  a company whose servers carry other companies' video. Your player asks for every piece, and each request can
  carry a token, so the server can tell a paying viewer's player from someone who copied the address.
- **Links that stop working.** A download link that says "this link has expired", or one that works for you but
  not for the friend you sent it to, is the same idea: the link carries terms, and the server checks them.
- **"Not available in your region."** Some video can only be shown in certain places. A token can carry that rule
  too, though services also enforce it in other ways.

## Where CAT comes from

CAT is a standard from the Consumer Technology Association (CTA-5007), written so that video services and the
networks that deliver their video can agree on one kind of ticket instead of each inventing their own. Several open
implementations exist, including ones from Fastly, a content delivery network, and from Eyevinn, a streaming
technology company. wtcat is another, written in Go, and its tests check it against tickets made by three of the
others.

## What's coming: live video with less delay

Live streams today usually run several seconds behind the real event, which is why a neighbour can cheer a goal
before you see it. Media over QUIC, or MoQ, is newer work at the Internet Engineering Task Force that aims to cut
that delay while still reaching very large audiences, for live video and also for things like games. A draft
standard describes how the same CAT tickets would work with MoQ, and wtcat already supports it: package `catmoqt`
is the door for a MoQ server.

## For the technical version

The [design explanation](design.md) says how wtcat is built and why, and the
[tutorial](../tutorials/protect-a-server.md) protects a small web server with it, step by step.
