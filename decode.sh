#!/bin/bash
awk '{ if(match($0,/<SQLTEXT encode="base64">.*<\/SQLTEXT>/))
{printf("%s<SQLTEXT>", substr($0,1,RSTART-1));
cmd=sprintf("echo -n %s|base64 -d", substr($0,RSTART+25,RLENGTH-35));
system(cmd);
printf("</SQLTEXT>\n");
}
else
{print $0;}
}' $1
