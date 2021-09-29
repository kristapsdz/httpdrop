(function(root) {
	'use strict';

	function find(root)
	{
		return (typeof root !== 'string') ?
			root : document.getElementById(root);
	}

	function show(name)
	{
		var e = find(name);

		if (e !== null && e.classList.contains('hide'))
			e.classList.remove('hide');
	}

	function hide(name)
	{
		var e = find(name);

		if (e !== null && !e.classList.contains('hide'))
			e.classList.add('hide');
	}

	function sendForm(e, setup, error, success, prog)
	{
		var xmh = new XMLHttpRequest();
		var url = e.action;

		if (setup !== null)
			setup(e);

		xmh.open(e.method, e.action, true);

		if (prog !== null)
			xmh.onprogress = function(evt) {
				if (evt.lengthComputable)
					prog(Math.round((evt.loaded * 100) / evt.total));
			};

		xmh.onreadystatechange = function() {
			if (xmh.readyState === 4 && xmh.status === 200) {
				if (success !== null)
					success();
			} else if (xmh.readyState === 4) {
				if (error !== null)
					error();
			}
		};

		xmh.send(new FormData(e));
		return false;
	}

	function initFileName()
	{
		var file, e;

		if ((e = find('file-name-no-file')) !== null)
			e.className = '';
		if ((e = find('file-name-has-file')) !== null)
			e.className = 'hide';

		if ((file = find('file-name-input')) !== null)
			file.onchange = function() {
				if (file.files.length === 0)
					return;
				e = find('file-name-has-file');
				if (e !== null)
					e.className = '';
				e = find('file-name-no-file');
				if (e !== null)
					e.className = 'hide';
			};
	}

	function initUploaderSetup()
	{
		var e = find('file-uploader-button');

		if (e !== null) {
			e.setAttribute('disabled', 'disabled');
			e.innerHTML = 'Uploading: 0%';
		}
	}

	function initUploaderProgress(percent)
	{
		var e = find('file-uploader-button');

		if (e !== null)
			e.innerHTML = 'Uploading: ' + percent + '%';
	}

	function initUploaderError()
	{
		var e = find('file-uploader-button');

		if (e !== null) {
			e.innerHTML = 'Uploading: failed';
			e.removeAttribute('disabled');
		}
	}

	function initUploaderFinish()
	{
		var e = find('file-uploader-button');

		if (e !== null) {
			e.innerHTML = 'Uploading: 100%';
			e.removeAttribute('disabled');
		}

		document.location.reload();
	}

	function chpassSuccess()
	{
		document.location.reload();
	}

	function chpassSetup()
	{
		hide('message-chpass-fail');
	}

	function chpassError()
	{
		show('message-chpass-fail');
	}

	function initUploader()
	{
		var formUploader, btnLogout, formChpass, list;

		if ((btnLogout = find('btn-logout')) !== null)
			btnLogout.onclick = function() {
				find('form-logout').submit();
			};

		list = document.getElementsByClassName('btn-chpass');

		for (var i = 0; i < list.length; i++)
			list[i].onclick = function() {
				find('chpass-modal').classList.toggle('is-active');
				return false;
			};

		if ((formUploader = find('file-uploader')) !== null)
			formUploader.onsubmit = function() {
				return sendForm(formUploader,
					initUploaderSetup,
					initUploaderError,
					initUploaderFinish,
					initUploaderProgress);
			}

		if ((formChpass = find('form-chpass')) !== null)
			formChpass.onsubmit = function() {
				return sendForm(formChpass,
					chpassSetup,
					chpassError,
					chpassSuccess,
					null);
			}
	}

	function initDocument()
	{
		initUploader();
		initFileName();
	}

	root.initDocument = initDocument;
})(this);

document.addEventListener('DOMContentLoaded', initDocument);
