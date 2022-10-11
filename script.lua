

process = Proto("process", "Process Name")           -- ���������� �������� ��� �������� ����� ��������
  
local p_name = ProtoField.string("process.name", "Process Name", base.STRING)    -- ���������� ��������� (����) ���������

process.fields = { p_name }                          -- ������������ ���� ���������


function process.dissector(buf, pinfo, tree)         -- ������� ����������   

    local ind = buf(16,2):uint()+14                  -- ����� �����, � �������� ���������� ��� ��������
    
    subtree = tree:add(process, buf(ind))            -- ������� ���������    

    local pr = buf(ind):string()                     -- �������� ��� ��������

    pr = string.gsub(pr, "%z", "")                   -- ������� � ������ ������� ������� (��� ������� � ����� padding)
    
    subtree:add(p_name, pr)                          -- ������� ���� � ���������  

    subtree:append_text(string.format(": %s", pr))   -- ������� ��� ��������
    
end


register_postdissector(process)                      -- ������������ � �������� ����-����������