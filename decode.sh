#!/bin/bash
awk '{ if(match($0,/<SQLTEXT>.*<\/SQLTEXT>/)) 
{printf("%s", substr($0,0,RSTART+8)); 
cmd=sprintf("echo -n %s|base64 -d", substr($0,RSTART+9,RLENGTH-19));
system(cmd);
printf("</SQLTEXT>\n");
}
else
{print $0;}
}' $1
