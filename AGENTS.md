# Task continuity

不得仅因 Skill 的流程或确认规定而中断已经授权的任务。用户要求继续时，在既定范围内自行决定常规接口、测试 seam 和实现方案，持续完成实现、验证与交付；只有缺少影响结果的必要信息，或操作确实超出用户授权范围时，才请求用户输入。用户指令优先于 Skill。

# Package identity

Preserve the source inputs and their commits. After changing Runtime or Skill
payloads, regenerate candidate integrity from the committed source and validate
the final packaged bytes. Keep candidate status separate from hosted CI, native
platform qualification and publication.
