# HackTheBox---Noxious Sherlock Writeup

In this Sherlock challenge, We analyze a ```.pcap``` file to uncover a credential-stealing attack leveraging the LLMNR protocol in a Windows environment. A simple user typo triggers a series of events, leading to the attacker using Responder to capture NTLMv2 hashes. The challenge teaches how such attacks occur internally, how to spot them in PCAP files, and how to crack captured hashes using information from SMB traffic.

## Task 1
We shall filter for

```udp.port == 5355```

As LLMNR runs over port 5355, running this filter displays all LLMNR traffic

![Screenshot From 2025-06-21 11-59-46](https://github.com/user-attachments/assets/6f940085-c944-4a2e-bf55-0f90b23d6a88)


## Task 2
We have to add a filter for the IP address and DHCP

```ip.addr == 172.17.79.135 && dhcp```

![Screenshot From 2025-06-21 12-03-29](https://github.com/user-attachments/assets/b1ce8352-403b-4760-abe5-9d3c41ad5692)


## Task 3
type ```smb2``` in the filter bar.

This shows traffic related to SMB version 2 (used for file sharing, and where authentication happens).

We see some NTLMSSP negotiate and auth

NTLMSSP = NTLM Security Support Provider. It’s the part of Windows authentication that handles password hashes.

If you see NTLMSSP_NEGOTIATE and NTLMSSP_AUTH, it means a login process happened — and possibly, a password hash was sent.

To further narrow down this, add the filter ```ntlmssp``` to show only NTLM authentication-related traffic.

```smb2 && ntlmssp```

![Screenshot From 2025-06-21 12-09-11](https://github.com/user-attachments/assets/fb71f400-5331-47cc-bd99-066a5ad0d971)


## Task 4
We need to modify the wireshark time display format to display in UTC. Go to View > Time display format > UTC DATE. Now the time column will show the time in UTC format

look at the the time of the first 3 packets starting from NTLMSSP_NEGOTIATE and ending in NTLMSSP_AUTH packet

![Screenshot From 2025-06-21 12-14-17](https://github.com/user-attachments/assets/43f91711-9999-4c70-8cb2-0b74dd167122)


## Task 5
While looking at LLMNR traffic we saw that the machine responded to a query
"DCC01" which means that the victim typed DCC01 instead of DC01

![Screenshot From 2025-06-21 13-24-04](https://github.com/user-attachments/assets/4f2bdc66-6851-440b-a9ca-9cc9770f9dc7)


## Task 6
for the NTLMSSP_CHALLENGE packet (Packet 9291)

▶ Server Message Block Protocol version 2 (SMB2)

▶ Session Setup Response (0x1)

▶ Security Blob

▶ GSS-API Generic

▶ Simple Protected Negotiation

▶ negTokenTarg

▶ NTLM Secure Service Provider

▶ NTLM Server Challenge

![Screenshot From 2025-06-21 13-30-42](https://github.com/user-attachments/assets/a543b8bb-77ab-4904-a8db-68a605d4c8aa)


## Task 7
for the NTLMSSP_AUTH packet (Packet 9292)

▶ Server Message Block Protocol version 2 (SMB2)

▶ Session Setup Response (0x1)

▶ Security Blob

▶ GSS-API Generic

▶ Simple Protected Negotiation

▶ negTokenTarg

▶ NTLM Secure Service Provider

▶ NTLM Response

▶ NTLMv2 Response

▶ NTProofStr

![Screenshot From 2025-06-21 13-34-02](https://github.com/user-attachments/assets/2ab1d03b-4170-4120-8a1d-9187d3e556b0)


## Task 8
We are going to use Hashcat for this

Create a .txt file and provide the following values 

User::Domain:ServerChallenge:NTProofStr:NTLMv2Response(without first 16 bytes)

<pre>
john.deacon::FORELA:601019d191f054f1:c0cc803a6d9fb5a9082253a04dbd4cd4:01010000000000
0080e4d59406c6da01cc3dcfc0de9b5f2600000000020008004e0042004600590001001e005700490
04e002d00360036004100530035004c003100470052005700540004003400570049004e002d00360
036004100530035004c00310047005200570054002e004e004200460059002e004c004f004300410
04c00030014004e004200460059002e004c004f00430041004c00050014004e004200460059002e00
4c004f00430041004c000700080080e4d59406c6da01060004000200000008003000300000000000
00000000000000200000eb2ecbc5200a40b89ad5831abf821f4f20a2c7f352283a35600377e1f294f1c
90a001000000000000000000000000000000000000900140063006900660073002f0044004300430
0300031000000000000000000  
</pre>


after saving this as a .txt file, we run Hashcat to crack the password

```hashcat -a0 -m5600 hashfile.txt /usr/share/wordlists/rockyou.txt```

![Screenshot From 2025-06-21 13-45-42](https://github.com/user-attachments/assets/5898754c-3785-4ec7-b2a8-06178ea18673)


## Task 9
under the ```smb2``` filter, we need to keep scrolling till we see tree connect/disconnect of a NON-DEFAULT File share name.

![Screenshot From 2025-06-21 13-49-15](https://github.com/user-attachments/assets/782836ab-c9d9-489f-88fa-f981c94d4020)

