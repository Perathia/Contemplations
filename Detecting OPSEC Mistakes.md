## Hypothesis: 
- 1.) Can remote access, through direct connections or C2 channels, be discovered from IOCs when non-English strings appear in the command line due to incorrect keyboard language settings?
  - 1a.) Can a threat actor who remotes into a machine and forgets to update their keyboard layout/bindings be detected through garbled command-line input?
  - 1b.) Can this be detected based on their keyboard layout (physical mapping) rather than the language?

### TL;DR: 
- It's unlikely that attackers would forget to change their keyboard language when remoting into a box, primarily because shells like CMD and Bash are inherently built for English commands. The operating system's chosen OS profile or keyboard language layout does not change the language of the inherent shell. I suspect it is more likely to catch an alias in a foreign language than, than forgetting to change the keyboard language input as English. Another concept is that there are some keyboard mappings where they do not align with QWERTY but that seems very rare to observe these days.

#### Additional Context:
- This idea stemmed from observing Chinese characters in malware samples. I began to wonder if, upon changing the language of a Linux or Windows machine, the shell commands themselves would change. Research confirmed they do not. Shells are built upon the English language and settings changed with the OS's GUI will not modify shell's syntax. You can create aliases or functions in foreign  languages, but I haven't found any evidence/reports that attackers have been observed do this.

---

### Keyboard Layouts vs. System Format:
- The layout of where keys are mapped on the external, hardware keyboard are detected by the format chosen on the OS. An external keyboard layout could be in English/QWERTY layout but the software/system’s format can be changed at anytime to another non-English format.
- For Example: If the threat actor is using a Russian keyboard than the layout will be JCUKEN (ЙЦУКЕН).
- After spending sometime reviewing a few different keyboard, it seems that today's keyboard usually map to the same as QWERTY.
  - I did find at least one keyboard's layout for an older Apple keyboard where the "8" key also had the shift "(".
    - Evidence suggests this is uncommon these days.
      - This relates to the Hypothesis '1.b' questions.

---

### Pre-Findings Concept: 
- I wanted to know if any of these 5 commands, if translated to Russian or Chinese could be utilized to detect an adversary. My favorite query language to build detections with is KQL. 

### Defender Query:

    // Define known command mappings
    let Cmd_Table = datatable(EN_Cmd:string, RU_Cmd:string, ZH_Cmd:string)[
        'ls','ды','中尸',
        'cd','св','金木',
        'dir','вшк','木戈口',
        'pwd','зцв','心田木',
        'who','црщ', '田竹人'
    ];
    let EN_Cmd_List = toscalar(Cmd_Table | summarize make_list(EN_Cmd));
    let RU_Cmd_List = toscalar(Cmd_Table | summarize make_list(RU_Cmd));
    let ZH_Cmd_List = toscalar(Cmd_Table | summarize make_list(ZH_Cmd));
    let SuspiciousEvents =
        DeviceProcessEvents
        | where ProcessCommandLine has_any (RU_Cmd_List) or ProcessCommandLine has_any (ZH_Cmd_List)
        | extend Sus_Timestamp = Timestamp
        | extend sus_ProcessCommandLine_Split = split(ProcessCommandLine, " ");
    DeviceProcessEvents
    | join kind=inner (SuspiciousEvents) on hostname
    | extend diff_time_minutes = datetime_diff('minute', Updated_Timestamp, Sus_Timestamp)
    | where diff_time_minutes >= 0 and diff_time_minutes <= 2
    | extend ProcessCommandLine_Split = split(tolower(ProcessCommandLine), " ")
    | extend EN_Matched = set_intersect(ProcessCommandLine_Split, EN_Cmd_List)
    | where array_length(EN_Matched) > 0
    | extend EN_Index = array_index_of(EN_Cmd_List, tostring(EN_Matched[0]))
    | extend RU_Matched = set_intersect(sus_ProcessCommandLine_Split, RU_Cmd_List)
    | extend ZH_Matched = set_intersect(sus_ProcessCommandLine_Split, ZH_Cmd_List)
    | extend RU_Index = array_index_of(RU_Cmd_List, tostring(RU_Matched[0]))
    | extend ZH_Index = array_index_of(ZH_Cmd_List, tostring(ZH_Matched[0]))
    | extend EN_Mapped = iif(EN_Index >= 0, EN_Cmd_List[EN_Index], "")
    | extend RU_Mapped = iif(RU_Index >= 0, RU_Cmd_List[RU_Index], "")
    | extend ZH_Mapped = iif(ZH_Index >= 0, ZH_Cmd_List[ZH_Index], "")
    | extend Diff_Time_Seconds = datetime_diff('second', Updated_Timestamp, Sus_Timestamp)
    | extend OPSEC_Values = bag_pack(
        "DiffTimeSeconds", Diff_Time_Seconds,
        "FirstIOC", RU_Mapped,
        "FirstIOCTimestamp", Sus_Timestamp,
        "SecondIOC", EN_Mapped,
        "SecondIOCTimestamp", Updated_Timestamp
    )
    | project-reorder Timestamp, OPSEC_Values, *

---

### Final Thoughts:
- This kind of detection is niche and relies on attackers making obvious OPSEC mistakes. Shell commands must be entered in English, so errors caused by incorrect keyboard layouts are usually corrected immediately.
- However, when such errors occur, they could be valuable pivot points in a broader hunt when utilizing past events. Detecting these anomalies will be very low probability and possibly never observed. However, I am curious to know the fidelity of it.
- This approach should not be prioritized over more reliable detection methods like unusual command execution paths, suspicious parent-child process relationships, or credential access patterns.
- The Defender query is a great to start build future detections on strings you expect to see followed by a future observations of a or multiple different strings.

---

### Special Thanks:
- To my good friend J. McIver and J. Killam who encouraged and helped me research this topic.
- Your expertise in Python and threat detection has tremendously helped me understand adversarial patterns and behaviors.

---

#### Your Support: 
- If you would like to share similar research or real-world findings that align close to my questions, then please make a comment.
- I would be thrilled to learn what has helped you detect abuse or similar threat intel/hunting concepts I should consider. Thanks for reading!
