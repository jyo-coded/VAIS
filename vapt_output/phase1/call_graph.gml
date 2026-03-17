graph [
  directed 1
  node [
    id 0
    label "greet_user"
    language "c"
    file "C:\ImpProjects\sysml\vapt_system\tests\samples\vulnerable.c"
    start_line 6
    end_line 10
    is_entry 0
    loop_depth 0
    pointer_ops 0
    extern_input 0
  ]
  node [
    id 1
    label "read_input"
    language "c"
    file "C:\ImpProjects\sysml\vapt_system\tests\samples\vulnerable.c"
    start_line 13
    end_line 18
    is_entry 0
    loop_depth 0
    pointer_ops 0
    extern_input 1
  ]
  node [
    id 2
    label "show_message"
    language "c"
    file "C:\ImpProjects\sysml\vapt_system\tests\samples\vulnerable.c"
    start_line 21
    end_line 23
    is_entry 0
    loop_depth 0
    pointer_ops 0
    extern_input 0
  ]
  node [
    id 3
    label "run_file"
    language "c"
    file "C:\ImpProjects\sysml\vapt_system\tests\samples\vulnerable.c"
    start_line 26
    end_line 30
    is_entry 0
    loop_depth 0
    pointer_ops 0
    extern_input 0
  ]
  node [
    id 4
    label "process_data"
    language "c"
    file "C:\ImpProjects\sysml\vapt_system\tests\samples\vulnerable.c"
    start_line 33
    end_line 39
    is_entry 0
    loop_depth 0
    pointer_ops 0
    extern_input 0
  ]
  node [
    id 5
    label "cleanup"
    language "c"
    file "C:\ImpProjects\sysml\vapt_system\tests\samples\vulnerable.c"
    start_line 42
    end_line 45
    is_entry 0
    loop_depth 0
    pointer_ops 0
    extern_input 0
  ]
  node [
    id 6
    label "build_query"
    language "c"
    file "C:\ImpProjects\sysml\vapt_system\tests\samples\vulnerable.c"
    start_line 48
    end_line 52
    is_entry 0
    loop_depth 0
    pointer_ops 0
    extern_input 0
  ]
  node [
    id 7
    label "copy_payload"
    language "c"
    file "C:\ImpProjects\sysml\vapt_system\tests\samples\vulnerable.c"
    start_line 55
    end_line 59
    is_entry 0
    loop_depth 0
    pointer_ops 0
    extern_input 0
  ]
  node [
    id 8
    label "main"
    language "c"
    file "C:\ImpProjects\sysml\vapt_system\tests\samples\vulnerable.c"
    start_line 61
    end_line 79
    is_entry 1
    loop_depth 0
    pointer_ops 6
    extern_input 1
  ]
  node [
    id 9
    label "strcpy"
    language "c"
    file "external"
    is_entry 0
    external 1
  ]
  node [
    id 10
    label "printf"
    language "c"
    file "external"
    is_entry 0
    external 1
  ]
  node [
    id 11
    label "gets"
    language "c"
    file "external"
    is_entry 0
    external 1
  ]
  node [
    id 12
    label "sprintf"
    language "c"
    file "external"
    is_entry 0
    external 1
  ]
  node [
    id 13
    label "system"
    language "c"
    file "external"
    is_entry 0
    external 1
  ]
  node [
    id 14
    label "malloc"
    language "c"
    file "external"
    is_entry 0
    external 1
  ]
  node [
    id 15
    label "free"
    language "c"
    file "external"
    is_entry 0
    external 1
  ]
  node [
    id 16
    label "memcpy"
    language "c"
    file "external"
    is_entry 0
    external 1
  ]
  node [
    id 17
    label "fprintf"
    language "c"
    file "external"
    is_entry 0
    external 1
  ]
  edge [
    source 0
    target 9
    line 8
  ]
  edge [
    source 0
    target 10
    line 9
  ]
  edge [
    source 1
    target 10
    line 17
  ]
  edge [
    source 1
    target 11
    line 16
  ]
  edge [
    source 2
    target 10
    line 22
  ]
  edge [
    source 3
    target 12
    line 28
  ]
  edge [
    source 3
    target 13
    line 29
  ]
  edge [
    source 4
    target 14
    line 34
  ]
  edge [
    source 4
    target 9
    line 36
  ]
  edge [
    source 4
    target 15
    line 37
  ]
  edge [
    source 4
    target 10
    line 38
  ]
  edge [
    source 5
    target 15
    line 44
  ]
  edge [
    source 6
    target 12
    line 50
  ]
  edge [
    source 6
    target 10
    line 51
  ]
  edge [
    source 7
    target 16
    line 57
  ]
  edge [
    source 7
    target 10
    line 58
  ]
  edge [
    source 8
    target 17
    line 63
  ]
  edge [
    source 8
    target 0
    line 67
  ]
  edge [
    source 8
    target 2
    line 68
  ]
  edge [
    source 8
    target 3
    line 69
  ]
  edge [
    source 8
    target 1
    line 70
  ]
  edge [
    source 8
    target 14
    line 72
  ]
  edge [
    source 8
    target 5
    line 73
  ]
  edge [
    source 8
    target 6
    line 75
  ]
  edge [
    source 8
    target 7
    line 76
  ]
]
