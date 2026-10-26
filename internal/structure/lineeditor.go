package structure

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"
)

var errLineInterrupted = errors.New("line interrupted")

type keyKind int

const (
	keyRune keyKind = iota
	keyEnter
	keyBackspace
	keyDelete
	keyLeft
	keyRight
	keyUp
	keyDown
	keyHome
	keyEnd
	keyTab
	keyCtrlC
	keyCtrlD
	keyCtrlL
	keyCtrlU
	keyCtrlK
	keyCtrlW
	keyCtrlA
	keyCtrlE
	keyEsc
)

type editorKey struct {
	kind keyKind
	r    rune
}

type lineCompleter func(line string, cursor int) (replaceStart int, candidates []string)

type lineEditor struct {
	in     *os.File
	out    io.Writer
	reader *bufio.Reader
}

func newLineEditor(in *os.File, out io.Writer) *lineEditor {
	return &lineEditor{
		in:     in,
		out:    out,
		reader: bufio.NewReader(in),
	}
}

// readLine runs one raw-mode editing session. It returns io.EOF on Ctrl-D at
// an empty line and errLineInterrupted on Ctrl-C.
func (e *lineEditor) readLine(prompt string, history []string, complete lineCompleter) (string, error) {
	oldState, err := term.MakeRaw(int(e.in.Fd()))
	if err != nil {
		return e.readLineCooked(prompt)
	}
	defer func() {
		_ = term.Restore(int(e.in.Fd()), oldState)
	}()

	var (
		buffer       string
		cursor       int
		historyIndex = len(history)
		draft        string
		renderedRows = 0
		width        = e.terminalWidth()
	)

	cursorPosition := func(column int) (row, col int) {
		if column <= 0 {
			return 0, 0
		}
		return (column - 1) / width, (column - 1) % width
	}

	redraw := func() {
		if renderedRows > 1 {
			e.writef("\x1b[%dA", renderedRows-1)
		}
		e.write("\r\x1b[J")
		e.write(prompt)
		e.write(buffer)

		promptWidth := getStringWidth(stripANSI(prompt))
		totalWidth := promptWidth + getStringWidth(buffer)
		cursorWidth := promptWidth + getStringWidth(buffer[:cursor])
		endRow, _ := cursorPosition(totalWidth)
		targetRow, targetCol := cursorPosition(cursorWidth)

		if endRow > targetRow {
			e.writef("\x1b[%dA", endRow-targetRow)
		}
		e.write("\r")
		if targetCol > 0 {
			e.writef("\x1b[%dC", targetCol)
		}
		renderedRows = endRow + 1
	}

	moveToEnd := func() {
		cursor = len(buffer)
		redraw()
	}

	insertRune := func(value rune) {
		text := string(value)
		buffer = buffer[:cursor] + text + buffer[cursor:]
		cursor += len(text)
	}

	backspace := func() {
		if cursor == 0 {
			return
		}
		_, size := utf8.DecodeLastRuneInString(buffer[:cursor])
		buffer = buffer[:cursor-size] + buffer[cursor:]
		cursor -= size
	}

	deleteForward := func() {
		if cursor >= len(buffer) {
			return
		}
		_, size := utf8.DecodeRuneInString(buffer[cursor:])
		buffer = buffer[:cursor] + buffer[cursor+size:]
	}

	deleteWord := func() {
		start := cursor
		for start > 0 {
			value, size := utf8.DecodeLastRuneInString(buffer[:start])
			if !unicode.IsSpace(value) {
				break
			}
			start -= size
		}
		for start > 0 {
			value, size := utf8.DecodeLastRuneInString(buffer[:start])
			if unicode.IsSpace(value) {
				break
			}
			start -= size
		}
		buffer = buffer[:start] + buffer[cursor:]
		cursor = start
	}

	for {
		redraw()
		key, err := e.readKey()
		if err != nil {
			moveToEnd()
			e.write("\r\n")
			return "", err
		}

		switch key.kind {
		case keyEnter:
			moveToEnd()
			e.write("\r\n")
			return buffer, nil
		case keyCtrlC:
			moveToEnd()
			e.write("^C\r\n")
			return "", errLineInterrupted
		case keyCtrlD:
			if buffer == "" {
				e.write("\r\n")
				return "", io.EOF
			}
			deleteForward()
		case keyBackspace:
			backspace()
		case keyDelete:
			deleteForward()
		case keyLeft:
			if cursor > 0 {
				_, size := utf8.DecodeLastRuneInString(buffer[:cursor])
				cursor -= size
			}
		case keyRight:
			if cursor < len(buffer) {
				_, size := utf8.DecodeRuneInString(buffer[cursor:])
				cursor += size
			}
		case keyHome:
			cursor = 0
		case keyEnd:
			cursor = len(buffer)
		case keyCtrlA:
			cursor = 0
		case keyCtrlE:
			cursor = len(buffer)
		case keyCtrlU:
			buffer = buffer[cursor:]
			cursor = 0
		case keyCtrlK:
			buffer = buffer[:cursor]
		case keyCtrlW:
			deleteWord()
		case keyCtrlL:
			e.write("\x1b[2J\x1b[H")
			renderedRows = 0
		case keyUp:
			if len(history) == 0 {
				continue
			}
			if historyIndex == len(history) {
				draft = buffer
			}
			if historyIndex > 0 {
				historyIndex--
				buffer = history[historyIndex]
				cursor = len(buffer)
			}
		case keyDown:
			if len(history) == 0 {
				continue
			}
			if historyIndex < len(history)-1 {
				historyIndex++
				buffer = history[historyIndex]
				cursor = len(buffer)
			} else if historyIndex < len(history) {
				historyIndex = len(history)
				buffer = draft
				cursor = len(buffer)
			}
		case keyTab:
			if complete == nil {
				continue
			}
			start, candidates := complete(buffer, cursor)
			candidates = filterCompletions(candidates, buffer[start:cursor])
			if len(candidates) == 0 {
				continue
			}
			common := longestCommonPrefix(candidates)
			prefix := buffer[start:cursor]
			if len(common) > len(prefix) {
				buffer = buffer[:start] + common + buffer[cursor:]
				cursor = start + len(common)
				continue
			}
			if len(candidates) == 1 {
				buffer = buffer[:start] + candidates[0] + buffer[cursor:]
				cursor = start + len(candidates[0])
				continue
			}
			moveToEnd()
			e.write("\r\n")
			printCompletionColumns(e.out, candidates)
			renderedRows = 0
		case keyRune:
			insertRune(key.r)
		case keyEsc:
		}
	}
}

func (e *lineEditor) write(text string) {
	_, _ = io.WriteString(e.out, text)
}

func (e *lineEditor) writef(format string, args ...any) {
	_, _ = fmt.Fprintf(e.out, format, args...)
}

func (e *lineEditor) terminalWidth() int {
	if width, _, err := term.GetSize(int(e.in.Fd())); err == nil && width > 0 {
		return width
	}
	return 80
}

func (e *lineEditor) readLineCooked(prompt string) (string, error) {
	e.write(prompt)
	line, err := e.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (e *lineEditor) readKey() (editorKey, error) {
	first, err := e.reader.ReadByte()
	if err != nil {
		return editorKey{}, err
	}

	switch first {
	case 3:
		return editorKey{kind: keyCtrlC}, nil
	case 4:
		return editorKey{kind: keyCtrlD}, nil
	case 8, 127:
		return editorKey{kind: keyBackspace}, nil
	case 9:
		return editorKey{kind: keyTab}, nil
	case 10, 13:
		return editorKey{kind: keyEnter}, nil
	case 1:
		return editorKey{kind: keyCtrlA}, nil
	case 2:
		return editorKey{kind: keyLeft}, nil
	case 5:
		return editorKey{kind: keyCtrlE}, nil
	case 6:
		return editorKey{kind: keyRight}, nil
	case 14:
		return editorKey{kind: keyDown}, nil
	case 16:
		return editorKey{kind: keyUp}, nil
	case 11:
		return editorKey{kind: keyCtrlK}, nil
	case 12:
		return editorKey{kind: keyCtrlL}, nil
	case 21:
		return editorKey{kind: keyCtrlU}, nil
	case 23:
		return editorKey{kind: keyCtrlW}, nil
	case 27:
		return e.readEscape()
	}

	if first < 32 {
		return editorKey{kind: keyEsc}, nil
	}

	buffer := []byte{first}
	expected := utf8ExpectedBytes(first)
	for len(buffer) < expected {
		next, readErr := e.reader.ReadByte()
		if readErr != nil {
			return editorKey{}, readErr
		}
		buffer = append(buffer, next)
	}
	value, size := utf8.DecodeRune(buffer)
	if value == utf8.RuneError && size <= 1 {
		return editorKey{kind: keyEsc}, nil
	}
	return editorKey{kind: keyRune, r: value}, nil
}

func (e *lineEditor) readEscape() (editorKey, error) {
	next, err := e.reader.ReadByte()
	if err != nil {
		return editorKey{kind: keyEsc}, nil
	}
	if next != '[' {
		return editorKey{kind: keyEsc}, nil
	}
	code, err := e.reader.ReadByte()
	if err != nil {
		return editorKey{kind: keyEsc}, nil
	}
	switch code {
	case 'A':
		return editorKey{kind: keyUp}, nil
	case 'B':
		return editorKey{kind: keyDown}, nil
	case 'C':
		return editorKey{kind: keyRight}, nil
	case 'D':
		return editorKey{kind: keyLeft}, nil
	case 'H':
		return editorKey{kind: keyHome}, nil
	case 'F':
		return editorKey{kind: keyEnd}, nil
	case '1', '3', '4', '7', '8':
		terminator, readErr := e.reader.ReadByte()
		if readErr != nil || terminator != '~' {
			return editorKey{kind: keyEsc}, nil
		}
		switch code {
		case '1', '7':
			return editorKey{kind: keyHome}, nil
		case '4', '8':
			return editorKey{kind: keyEnd}, nil
		case '3':
			return editorKey{kind: keyDelete}, nil
		}
	}
	return editorKey{kind: keyEsc}, nil
}

func utf8ExpectedBytes(first byte) int {
	switch {
	case first&0xE0 == 0xC0:
		return 2
	case first&0xF0 == 0xE0:
		return 3
	case first&0xF8 == 0xF0:
		return 4
	default:
		return 1
	}
}

func filterCompletions(candidates []string, prefix string) []string {
	lowerPrefix := strings.ToLower(prefix)
	seen := map[string]struct{}{}
	result := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate == "" || !strings.HasPrefix(strings.ToLower(candidate), lowerPrefix) {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		result = append(result, candidate)
	}
	sort.Strings(result)
	return result
}

func longestCommonPrefix(values []string) string {
	if len(values) == 0 {
		return ""
	}
	prefix := values[0]
	for _, value := range values[1:] {
		for !strings.HasPrefix(value, prefix) {
			if prefix == "" {
				return ""
			}
			prefix = prefix[:len(prefix)-1]
		}
	}
	return prefix
}

func printCompletionColumns(writer io.Writer, values []string) {
	width := 80
	if terminalWidth, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && terminalWidth > 0 {
		width = terminalWidth
	}
	columnWidth := 0
	for _, value := range values {
		if valueWidth := getStringWidth(value); valueWidth > columnWidth {
			columnWidth = valueWidth
		}
	}
	columnWidth += 2
	if columnWidth < 12 {
		columnWidth = 12
	}
	columns := width / columnWidth
	if columns < 1 {
		columns = 1
	}

	for index, value := range values {
		_, _ = fmt.Fprint(writer, padString(value, columnWidth))
		if (index+1)%columns == 0 || index == len(values)-1 {
			_, _ = fmt.Fprint(writer, "\r\n")
		}
	}
}

func stripANSI(value string) string {
	var builder strings.Builder
	escape := false
	for _, char := range value {
		if escape {
			if char == 'm' {
				escape = false
			}
			continue
		}
		if char == 0x1b {
			escape = true
			continue
		}
		builder.WriteRune(char)
	}
	return builder.String()
}
