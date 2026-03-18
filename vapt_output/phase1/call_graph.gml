graph [
  directed 1
  node [
    id 0
    label "runCommand"
    language "go"
    file "C:\Users\Lakshya\VAIS\vulnerability.go"
    start_line 10
    end_line 12
    is_entry 0
    loop_depth 0
    pointer_ops 0
    extern_input 0
  ]
  node [
    id 1
    label "runSystem"
    language "go"
    file "C:\Users\Lakshya\VAIS\vulnerability.go"
    start_line 15
    end_line 17
    is_entry 0
    loop_depth 0
    pointer_ops 0
    extern_input 0
  ]
  node [
    id 2
    label "weakRandom"
    language "go"
    file "C:\Users\Lakshya\VAIS\vulnerability.go"
    start_line 20
    end_line 22
    is_entry 0
    loop_depth 0
    pointer_ops 0
    extern_input 0
  ]
  node [
    id 3
    label "writeFile"
    language "go"
    file "C:\Users\Lakshya\VAIS\vulnerability.go"
    start_line 25
    end_line 27
    is_entry 0
    loop_depth 0
    pointer_ops 0
    extern_input 0
  ]
  node [
    id 4
    label "readInput"
    language "go"
    file "C:\Users\Lakshya\VAIS\vulnerability.go"
    start_line 30
    end_line 33
    is_entry 0
    loop_depth 0
    pointer_ops 0
    extern_input 1
  ]
  node [
    id 5
    label "main"
    language "go"
    file "C:\Users\Lakshya\VAIS\vulnerability.go"
    start_line 35
    end_line 41
    is_entry 1
    loop_depth 0
    pointer_ops 0
    extern_input 0
  ]
  node [
    id 6
    label "exec.Command(&#34;bash&#34;, &#34;-c&#34;, input).Run"
    language "go"
    file "external"
    is_entry 0
    external 1
  ]
  node [
    id 7
    label "exec.Command"
    language "go"
    file "external"
    is_entry 0
    external 1
  ]
  node [
    id 8
    label "exec.Command(&#34;sh&#34;, &#34;-c&#34;, cmd).Run"
    language "go"
    file "external"
    is_entry 0
    external 1
  ]
  node [
    id 9
    label "os.WriteFile"
    language "go"
    file "external"
    is_entry 0
    external 1
  ]
  node [
    id 10
    label "fmt.Scanf"
    language "go"
    file "external"
    is_entry 0
    external 1
  ]
  node [
    id 11
    label "fmt.Println"
    language "go"
    file "external"
    is_entry 0
    external 1
  ]
  edge [
    source 0
    target 6
    line 11
  ]
  edge [
    source 0
    target 7
    line 11
  ]
  edge [
    source 1
    target 8
    line 16
  ]
  edge [
    source 1
    target 7
    line 16
  ]
  edge [
    source 3
    target 9
    line 26
  ]
  edge [
    source 4
    target 10
    line 32
  ]
  edge [
    source 5
    target 0
    line 36
  ]
  edge [
    source 5
    target 1
    line 37
  ]
  edge [
    source 5
    target 3
    line 38
  ]
  edge [
    source 5
    target 4
    line 39
  ]
  edge [
    source 5
    target 11
    line 40
  ]
  edge [
    source 5
    target 2
    line 40
  ]
]
