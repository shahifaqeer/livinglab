import urwid
import logging

class Dialog():
    """Generates a modal popup dialog window.
    
    Parameters:
        
        - main_frame: The frame that represents the entire graphical interface
        - msg: The text message that the user will see 
        - choices: The list of choices the user will visualize
        - action: The action that should be executed when a button is selected
        - action_params: The parameter that each choice passes to the action
                   
    The action receives one input parameter. The parameter is the corresponding
    value of the action_params list.
    """

    def __init__(self, main_frame, text, choices, action=None, action_params=None):
        self._main_frame = main_frame
        self._original_frame_body = self._main_frame.contents["body"]
        self._action = action
        
        self._logger = logging.getLogger(__name__)

        self._open_popup(text, choices, action, action_params)


    
    def _open_popup(self, text, choices, action, action_params):
        self._logger.debug("Opening popup. Text %s" % text)
        
        l = [urwid.AttrMap(urwid.Text(text), "popup-title"),
             urwid.Divider("-")]

        for choice_id in range(len(choices)):
            button = urwid.Button(choices[choice_id])

            action = None
            if (action_params is not None):
                action = action_params[choice_id]

            urwid.connect_signal(button, "click", self._close_popup_exec_action, action)
            l.append(button)

        linebox = urwid.LineBox(urwid.ListBox(urwid.SimpleListWalker(l)))

        overlay = urwid.Overlay(linebox, urwid.SolidFill(u'\N{MEDIUM SHADE}'),
            align='center', width=('relative', 60), valign='middle',
            height=('relative', 60), min_width=20, min_height=9)

        self._main_frame.contents["body"] = (overlay, None)    



    def _close_popup_exec_action(self, button, data=None):
        self._logger.debug("Closing popup. Button %s selected" % button.get_label())
        
        self._main_frame.contents["body"] = self._original_frame_body
        
        if (self._action is not None):
            self._logger.debug("Executing action for button %s" % button.get_label())
            self._action(data)
