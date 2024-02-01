---
title: Day 10 - Hack a Game
desc: >-
  Day 10 presents topics related to data storage in memory. Simple tools to find
  and alter the data in memory are introduced along with effects of changing
  data in memory on a running software.
---
## Introduction
An executed program has all its data processed through the computer's RAM. Modifying contents of the memory address of a running software can have unintended effects on its operation and functionality.

Cetus is a simple browser plugin that enables exploration of the memory space of Web Assembly games that run in your browser. The main premise behind the tool is to provide a simple method to find any piece of data stored in memory and modify it as needed. You can also modify a game's compiled code and alter its behaviour.

## CTF Questions

The guard wants us to guess a number between 1 and 99999999 (most likely a 32 bit integer). If the number we guess is correct, he will open the door and provide the Guard's flag. 

With `Cetus` fired up, lets make a random guess of `9`. The guard's number was `68275416`. Let's see where that number is stored in the memory space. Looks like the the game writes the guard's number at memory address `0x0411ccd8`. Note that all data is written in `hexadecimal` in the memory space.

Since we know the memory address of where the guard's number is stored, we can modify the value to be whatever we desire. Talk to the guard again and prior to entering a new guess, modify the data at the memory address `0x0411ccd8` to and arbitrary value of `99` or `0x63` in hex. Entering the modified value in the dialog box with the guard allows us to obtain the his flag: `THM{5_star_Fl4gzzz}`.

In order to get the Yeti's flag we need to get pass through a gauntlet of snowballs which reduce your overall HP every time you are struck by a ball. Since HP must be stored as a value in the memory space, we can use a `Differential Search` in `Cetus` to find the memory address where the HP data is stored. The process would be a to search the memory space for values which are consistently decreasing every time our HP is lost. For this we can use the `LT` or less than comparison operator.

Initial `Differential Search` reveals 458753 results. Let's get hit by a snowball to reduce our HP and refine our search further. Looks like the HP data is stored at memory address `0x0004b4a4`. Let's modify value stored at that address to be a really high value (say 9999) such that we can pass through the snowball barrage without loosing all our HP and get Yet's flag: `THM{yetiyetiyetiflagflagflag}`