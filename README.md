# WlanLoginBypass

Program to bypass wlan login implemented as a website and filtering users by MAC. 
A list of all users in a network is aquired by listening for ARP packets using the
winpcap library. Then the program tries for every user to change the machines MAC
address using registry entries and rebooting the network card.

This program does not work correctly, because windows forbids to change the MAC
to specific ranges used by common devices. The functionality without this does fully work.
