# mixfit
Mixfit is a greatly simplified version of [YAMN](https://github.com/crooks/yamn),  
which allows users to create YAMN-compatible  
payloads for anonymous email communication. The  
idea for this came about because, back in the  
1990s, there was also Mixfit for Macintosh users,  
which created payloads for Mixmaster remailers.  

Mixfit has only one parameter for creating payloads  
and is ideal for sending them with [Mini Mailer](https://github.com/Ch1ffr3punk/mmg), [Nym  
Mailer](https://github.com/Ch1ffr3punk/NymMailer), or any web mailer.  

Example message.txt:  

To: alice@example.org  
Subject: Hello Bob  

Hi Alice,  

I arrived at my hotel yesterday 21:00 PM.  
See you next week.  

Best regards  
Bob  

Mixfit looks in the current directory for pubring.mix and mlist2.txt.  
You will have to update the two files manually on a daily basis.  
Maximum message size is 17920 bytes.

```
$ mixfit -h  
Usage: mixfit -l remailer1,remailer2... < message.txt > outfile.txt
  
  -l string  
        Remailer chain (*,*,*... up to 10)  
```

If you like Mixfit consider to buy me a coffee.

<a href="https://www.buymeacoffee.com/Ch1ffr3punk" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-yellow.png" alt="Buy Me A Coffee" height="41" width="174"></a>

Mixfit is dedicated to Alice and Bob.  
