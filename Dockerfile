FROM  ubuntu

ADD . .

EXPOSE  2022
CMD ["./honeypot"]
