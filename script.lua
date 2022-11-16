
process = Proto("process", "Process Name")           -- определяем протокол для хранения имени процесса
  
local p_name = ProtoField.string("process.name", "Process Name", base.STRING)    -- определяем заголовок (поле) протокола

process.fields = { p_name }                          -- регистрируем поле протокола


function process.dissector(buf, pinfo, tree)         -- функция диссектора   

    local ind = buf(16,2):uint()+14                  -- номер байта, с которого начинается имя процесса
    
    subtree = tree:add(process, buf(ind))            -- создаем поддерево    
    
    local pr = ""                                    -- переменная для хранения имени процесса

    if (ind == 14) then                              -- применимо только для пакетов с TSO, у которых ip.len == 0

        local a = buf:bytes()                        -- переводим пакет в массив байтов (hex)

    	for i = 1, a:len()-1 do

        	if ((a:get_index(i) < 32) or (a:get_index(i) > 126)) then

			a:set_index(i, 32)           -- удаляем из содержимого непечатные символы (для корректной работы gsub)
		end

                pr = pr .. string.char(a:get_index(i))	 -- формируем строку без непечатных символов
    	end
        
    else

    	pr = buf(ind):string()                       -- получаем строку, содержащую имя процесса

    end
          
    pr = string.gsub(pr, ".*prc_name:", "")          -- удаляем в строке лишние символы (при наличии padding)

    subtree:add(p_name, pr)                          -- создаем поле в поддереве  

    subtree:append_text(string.format(": %s", pr))   -- выводим имя процесса
    
end

register_postdissector(process)                      -- регистрируем в качестве пост-диссектора