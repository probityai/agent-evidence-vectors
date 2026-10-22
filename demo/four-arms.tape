# Records demo/four-arms.sh as demo/four-arms.gif. Run from the repository root:
#   vhs demo/four-arms.tape
# The output is the script's own output, filtered to the arm headers, verdicts
# and results so the four outcomes fit on one screen.

Output demo/four-arms.gif

Require uv
Require grep

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 560
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms
Set Framerate 24

Hide
Type "export PS1='$ ' && clear"
Enter
Show

Type "uv run -q --no-project --with cryptography ./demo/four-arms.sh | grep -E '^===|^verdict|ARM RESULT|^all four'"
Sleep 400ms
Enter
Wait+Screen@60s /all four arms/
Sleep 6s
