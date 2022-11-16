
process = Proto("process", "Process Name")           -- ���������� �������� ��� �������� ����� ��������
  
local p_name = ProtoField.string("process.name", "Process Name", base.STRING)    -- ���������� ��������� (����) ���������

process.fields = { p_name }                          -- ������������ ���� ���������


function process.dissector(buf, pinfo, tree)         -- ������� ����������   

    local ind = buf(16,2):uint()+14                  -- ����� �����, � �������� ���������� ��� ��������
    
    subtree = tree:add(process, buf(ind))            -- ������� ���������    
    
    local pr = ""                                    -- ���������� ��� �������� ����� ��������

    if (ind == 14) then                              -- ��������� ������ ��� ������� � TSO, � ������� ip.len == 0

        local a = buf:bytes()                        -- ��������� ����� � ������ ������ (hex)

    	for i = 1, a:len()-1 do

        	if ((a:get_index(i) < 32) or (a:get_index(i) > 126)) then

			a:set_index(i, 32)           -- ������� �� ����������� ���������� ������� (��� ���������� ������ gsub)
		end

                pr = pr .. string.char(a:get_index(i))	 -- ��������� ������ ��� ���������� ��������
    	end
        
    else

    	pr = buf(ind):string()                       -- �������� ������, ���������� ��� ��������

    end
          
    pr = string.gsub(pr, ".*prc_name:", "")          -- ������� � ������ ������ ������� (��� ������� padding)

    subtree:add(p_name, pr)                          -- ������� ���� � ���������  

    subtree:append_text(string.format(": %s", pr))   -- ������� ��� ��������
    
end

register_postdissector(process)                      -- ������������ � �������� ����-����������