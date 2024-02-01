---
title: Day 14 - Web Applications
desc: >-
  Day 14 covers topics related to web application vulnerabilities; specifically
  vulnerabilities related to Broken Access Control and IDOR.
---
Browse to `http://10.10.57.168:8080` and authenticate with `mcskidy:devtest`.

Navigate to `http://10.10.57.168:8080/users/105` to reach `Elf Pivot McRed` profile page. The office number listed on profile is `134`.

Right-click on any image on the profile and copy the image location. Paste the address into the address bar and modify the URL to `10.10.57.168:8080/images/100.png` to retrieve the flag `THM{CLOSE_THE_DOOR}`