run: 	python feeds.py -aF "mal_ip" https://gist.githubusercontent.com/BBcan177/bf29d47ea04391cb3eb0/raw/
run:	python feeds.py -aF "mal_ip" "https://www.binarydefense.com/banlist.txt"
after that:	python feeds.py -uF 


now check in mongodb compass every feed will have two collection , CTI_<feed_type> will have redundant(removed duplicity) and will used in analyzation and comparison


