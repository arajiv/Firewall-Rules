# Firewall-Rules
Determines if an input packet matches a rule generated from a file containing rules. 


I initially unit tested my solution by first making sure it worked for simple inputs (using no ranges). Then I added 
functionality to port ranges and unit tested that. I then added the IP ranges adding full functionality to the program and 
tested various inputs using a combination of both port and IP ranges. 

I used a HashSet to store all of the rules - it uses the least amount of space, however, generating each individual rule and 
adding it to the HashSet took a lot of time. So, I used a HashMap that mapped ranges to its outputs (like a cache) so that if I
encountered a rule that had a range the program generated before, it would just access the HashMap instead of generating it over 
again. 

If I had more time, I would use cache-like HashMaps to store various combinations of port/ip ranges so that it would optimize
the time performance of the program. However, as of now, I only have it storing encountered ranges. 


I am very interested in the Data team not only because I have the most experience in that field, but also because I love to work
with data and I understand how powerful using data in the correct way can be. I want the opportunity to work with large volumes
of data in order to make conclusions about a certain hypothesis. 
