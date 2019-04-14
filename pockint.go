package main

import (
	"fmt"
	"github.com/therecipe/qt/widgets"
	"os"
)

var (
	appVersion = "1.0.0-beta"
	appTitle   = fmt.Sprintf("POCKINT v.%s", appVersion)
)

func main() {

	// needs to be called once before you can start using the QWidgets
	app := widgets.NewQApplication(len(os.Args), os.Args)

	window := widgets.NewQMainWindow(nil, 0)
	window.SetMinimumSize2(450, 200)
	window.SetWindowTitle(appTitle)

		// create a regular widget
	// give it a QVBoxLayout
	// and make it the central widget of the window
	widget := widgets.NewQWidget(nil, 0)
	widget.SetLayout(widgets.NewQVBoxLayout())
	window.SetCentralWidget(widget)

	// create a line edit
	// with a custom placeholder text
	// and add it to the central widgets layout
	input := widgets.NewQLineEdit(nil)
	input.SetPlaceholderText("Input data ...")
	widget.Layout().AddWidget(input)

	options := widgets.NewQComboBox(nil)
	widget.Layout().AddWidget(options)

	// make the window visible and start main Qt event loop
	window.Show()
	app.Exec()

}
