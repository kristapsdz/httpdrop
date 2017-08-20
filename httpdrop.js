document.addEventListener('DOMContentLoaded', function() {
	'use strict';

	var file, e;

	file = document.getElementById('file-name-input');
	if (null === file)
		return;

	e = document.getElementById('file-name-no-file');
	if (null !== e)
		e.className = '';
	e = document.getElementById('file-name-has-file');
	if (null !== e)
		e.className = 'hide';

	file.onchange = function() {
		if (file.files.length > 0) {
			e = document.getElementById('file-name-has-file');
			if (null !== e)
				e.className = '';
			e = document.getElementById('file-name-no-file');
			if (null !== e)
				e.className = 'hide';
		}
	};
});
