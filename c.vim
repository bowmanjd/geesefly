"vimrc: au BufEnter *.c,*.h,*.cpp,*.hpp,*.cc source ~/.vim/c.vim
set noexpandtab                
set tabstop=8                  
set shiftwidth=8               
set textwidth=78               
set autoindent smartindent     
set smarttab                   
set backspace=eol,start,indent 
nmap <C-J> vip=
syn keyword cType uint ubyte ulong uint64_t uint32_t uint16_t uint8_t boolean_t int64_t int32_t int16_t int8_t u_int64_t u_int32_t u_int16_t u_int8_t
syn keyword cOperator likely unlikely
syn match ErrorLeadSpace /^ \+/         " highlight any leading spaces
syn match ErrorTailSpace / \+$/         " highlight any trailing spaces
syn match Error80            /\%>80v.\+/    " highlight anything past 80 in red

if has("gui_running")
        hi Error80        gui=NONE   guifg=#ffffff   guibg=#6e2e2e
        hi ErrorLeadSpace gui=NONE   guifg=#ffffff   guibg=#6e2e2e
        hi ErrorTailSpace gui=NONE   guifg=#ffffff   guibg=#6e2e2e
else
        exec "hi Error80        cterm=NONE   ctermfg=" . <SID>X(79) . " ctermbg=" . <SID>X(32)
        exec "hi ErrorLeadSpace cterm=NONE   ctermfg=" . <SID>X(79) . " ctermbg=" . <SID>X(33)
        exec "hi ErrorTailSpace cterm=NONE   ctermfg=" . <SID>X(79) . " ctermbg=" . <SID>X(33)
endif

set formatoptions=tcqlron
set cinoptions=:0,l1,t0,g0
set foldmethod=syntax
