

process = Proto("process", "Process Name")           -- определяем протокол для хранения имени процесса
  
local p_name = ProtoField.string("process.name", "Process Name", base.STRING)    -- определяем заголовок (поле) протокола

process.fields = { p_name }                          -- регистрируем поле протокола


function process.dissector(buf, pinfo, tree)         -- функция диссектора   

    local ind = buf(16,2):uint()+14                  -- номер байта, с которого начинается имя процесса
    
    subtree = tree:add(process, buf(ind))            -- создаем поддерево    

    local pr = buf(ind):string()                     -- получаем имя процесса

    pr = string.gsub(pr, "%z", "")                   -- удаляем в строке нулевые символы (при наличии в кадре padding)
    
    subtree:add(p_name, pr)                          -- создаем поле в поддереве  

    subtree:append_text(string.format(": %s", pr))   -- выводим имя процесса
    
end


register_postdissector(process)                      -- регистрируем в качестве пост-диссектора