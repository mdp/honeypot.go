## Go SSH Honeypot

I stole most of this code from https://gist.github.com/nictuku/2338048
This is my first attempt at a Golang project, please excuse the terrible code.

### Goals

I wanted to get an idea of how often someone tries to SSH into my public machine

- Runs a fake SSH server on port 22
- When people try and login, and you've got it configured, you'll get a push notification to your phone
- Attempts are cached, you'll only get one per IP. So someone hammering your server won't result in thousands
of push notifications.


### Install

    make
    sudo docker build .
    sudo docker run -p 22:2022 imageId

### Bonus points

Add your Pushover keys to conf.json and this will push you notifications when someone new tries to ssh into your server

#### License - MIT

