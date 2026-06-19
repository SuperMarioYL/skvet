# vhs tape for skvet — renders assets/demo.gif
# Run with: vhs assets/demo.tape
#
# Story: scan a skill bundle, the findings table renders, and skvet prints
# RISK: HIGH with the load-bearing "stars ≠ safe" line.

Output assets/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 760
Set Padding 22
Set Theme "Dracula"
Set TypingSpeed 55ms

# Build the binary up front (kept off-camera-ish, fast).
Hide
Type "go build -o /tmp/skvet ." Enter
Sleep 4s
Type "clear" Enter
Show

# 1. The user is about to install a trending skill bundle.
Type "# about to install a trending agent-skill bundle — check it first"
Enter
Sleep 1500ms

# 2. Run the scan against the committed fixture (stands in for a cloned repo).
Type "/tmp/skvet scan ./testdata/fixtures/malicious-skill"
Sleep 800ms
Enter

# 3. Findings table renders: red shell/hook, yellow network.
Sleep 4500ms

# 4. Let the OVERALL RISK: HIGH + "stars ≠ safe" line sit on screen.
Sleep 3500ms

# 5. Same verdict, machine-readable.
Type "# pipe the same verdict into other tooling"
Enter
Sleep 1200ms
Type "/tmp/skvet scan ./testdata/fixtures/malicious-skill --json | head -n 20"
Sleep 600ms
Enter
Sleep 4000ms

Sleep 2s
