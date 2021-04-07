global s : table[addr] of set[string] = table();
event http_header (c: connection, is_orig: bool, name: string, value: string)
{
    if(name=="USER-AGENT")
    {
            if(c$id$orig_h in s)
            {
                    if(!(to_lower(value) in s[c$id$orig_h]))
                    {
                            add s[c$id$orig_h][to_lower(value)];
                    }
            }
            else
            {
                   s[c$id$orig_h]=set(to_lower(value));
            }
    }
}
event zeek_done()
{
	for (Addr, Set in s)
	{
		if(|Set|>=3)
		{
			print fmt("%s is a proxy",Addr);
		}
	}
}
