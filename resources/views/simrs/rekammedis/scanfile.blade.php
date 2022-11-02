@extends('adminlte::page')

@section('title', 'Scan E-File Rekam Medis')

@section('content_header')
    <h1>Scan E-Fileasdasd Rekam Medis</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-12">
            <x-adminlte-card title="Data E-File Rekam Medis" theme="warning" collapsible>
                {{-- scanner localhost --}}
                {{-- <button class="btn btn-primary" type="button" onclick="scanToLocalDisk();">Scan</button>
                <div id="response"></div> --}}

                {{-- <x-adminlte-input name="Tanggal Kunjungan" label="Nama Pasien" /> --}}
                {{-- <x-adminlte-input name="Tanggal Kunjungan" label="Nama Pasien" /> --}}
                {{-- scanner upload --}}
                <form id="form1" action="http://192.168.2.30/antrian/public/scanner/real.php?action=upload" method="POST"
                    enctype="multipart/form-data" target="_blank">
                    @php
                        $config = ['format' => 'YYYY-MM-DD HH:MM:SS'];
                    @endphp
                    <div class="row">
                        <div class="col-md-6">
                            <x-adminlte-input fgroup-class="norm" name="norm" label="No RM" type="number">
                                <x-slot name="appendSlot">

                                    <x-adminlte-button onclick="cekPasien();" theme="success" label="Cek" />
                                </x-slot>
                            </x-adminlte-input>
                            <x-adminlte-input readonly name="nomorkartu" label="No Kartu BPJS" />
                            <x-adminlte-input readonly name="nik" label="NIK" />
                        </div>
                        <div class="col-md-6">
                            <x-adminlte-input readonly name="nama" label="Nama Pasien" />
                            <x-adminlte-input readonly name="tanggallahir" label="Tanggal Lahir" />
                            <x-adminlte-input name="nohp" label="No HP" />
                        </div>
                    </div>
                    <x-adminlte-select name="jenisberkas" label="Jenis Berkas E-File">
                        <option value="4">Berkas Pasien</option>
                        <option value="1">Rawat Inap</option>
                        <option value="2">Rawan Jalan</option>
                        <option value="3">Penunjang</option>
                    </x-adminlte-select>
                    <x-adminlte-input name="namafile" label="Keterangan E-File" placeholder="Keterangan E-File" />
                    <x-adminlte-input-date name="tanggalscan" label="Tanggal Scan E-File" :config="$config"
                        value="{{ \Carbon\Carbon::now() }}">
                        <x-slot name="prependSlot">
                            <div class="input-group-text bg-primary">
                                <i class="fas fa-calendar-alt"></i>
                            </div>
                        </x-slot>
                    </x-adminlte-input-date>
                    <x-adminlte-input readonly name="fileurl" label="URL E-File RM" />
                    <button type="button" class="btn btn-primary" onclick="scanToPdfWithThumbnails();">Scan</button>
                    <input type="button" class="btn btn-success" value="Submit" onclick="submitFormWithScannedImages();">
                    <button type="button" class="btn btn-primary" onclick="simpanDatabase();">Simpan Database</button>
                </form>
                <div id="server_response"></div>
                {{-- image base64 --}}
                {{-- <img src="data:image/png;base64,{{ base64_encode($im_blob) }}" width="500" alt="Red dot" /> --}}
            </x-adminlte-card>
            <x-adminlte-card title="Data Scan E-File Rekam Medis" theme="warning" collapsible>
                <div id="images"></div>
                {{-- <div class="row">
                    <div class="col-6">
                        <iframe src="{{ asset('scanner/tmp/22101213221593383.pdf') }}" width="100%" height="500px">
                        </iframe>
                    </div>
                </div> --}}

            </x-adminlte-card>
        </div>
        {{-- <div class="col-12">
            <div class="card card-primary">
                <div class="card-header">
                    <h4 class="card-title">Ekko Lightbox</h4>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-sm-2">
                            <a href="https://via.placeholder.com/1200/FFFFFF.png?text=1" data-toggle="lightbox"
                                data-title="sample 1 - white" data-gallery="gallery">
                                <img src="data:image/png;base64,{{ base64_encode($im_blob) }}" class="img-fluid mb-2"
                                    alt="Red dot" />
                            </a>
                        </div>
                        <div class="col-sm-2">
                            <a href="https://via.placeholder.com/1200/FFFFFF.png?text=1" data-toggle="lightbox"
                                data-title="sample 1 - white" data-gallery="gallery">
                                <img src="https://via.placeholder.com/300/FFFFFF?text=1" class="img-fluid mb-2"
                                    alt="white sample" />
                            </a>
                        </div>
                        <div class="col-sm-2">
                            <a href="https://via.placeholder.com/1200/000000.png?text=2" data-toggle="lightbox"
                                data-title="sample 2 - black" data-gallery="gallery">
                                <img src="https://via.placeholder.com/300/000000?text=2" class="img-fluid mb-2"
                                    alt="black sample" />
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div> --}}
    </div>
@stop

@section('plugins.EkkoLightBox', true)

@section('css')
    <link rel="stylesheet" href="{{ asset('vendor/scannerjs/scanner.css') }}">
@endsection
@section('js')
    {{-- <script src="https://cdn.asprise.com/scannerjs/scanner.js" type="text/javascript"></script> --}}
    <script src="{{ asset('vendor/scannerjs/scanner.js') }} " type="text/javascript"></script>
    <script src="{{ asset('vendor/sweetalert2/sweetalert2.all.min.js') }}"></script>
    {{-- localhost --}}
    <script>
        /** Initiates a scan */
        function scanToLocalDisk() {
            var storagePath = '{{ str_replace('\\', '\\\\', storage_path()) }}';
            scanner.scan(displayResponseOnPage, {
                "output_settings": [{
                    "type": "save",
                    "format": "jpg",
                    "save_path": storagePath + "\\${TMS}${EXT}"
                }]
            });
        }

        function displayResponseOnPage(successful, mesg, response) {
            if (!successful) { // On error
                document.getElementById('response').innerHTML = 'Failed: ' + mesg;
                return;
            }

            if (successful && mesg != null && mesg.toLowerCase().indexOf('user cancel') >= 0) { // User cancelled.
                document.getElementById('response').innerHTML = 'User cancelled';
                return;
            }

            document.getElementById('response').innerHTML = scanner.getSaveResponse(response);
        }
    </script>
    {{-- upload --}}
    <script>
        /** Scan: output PDF original and JPG thumbnails */
        function scanToPdfWithThumbnails() {
            scanner.scan(displayImagesOnPage, {
                "output_settings": [{
                        "type": "return-base64",
                        "format": "pdf",
                        "pdf_force_black_white": true,
                        "pdf_text_line": "By ${USERNAME} on ${DATETIME}"
                    },
                    {
                        "type": "return-base64-thumbnail",
                        "format": "jpg",
                        "thumbnail_height": 400
                    }
                ]
            });
        }

        /** Processes the scan result */
        function displayImagesOnPage(successful, mesg, response) {
            if (!successful) { // On error
                console.error('Failed: ' + mesg);
                return;
            }

            if (successful && mesg != null && mesg.toLowerCase().indexOf('user cancel') >= 0) { // User cancelled.
                console.info('User cancelled');
                return;
            }

            var scannedImages = scanner.getScannedImages(response, true, false); // returns an array of ScannedImage
            for (var i = 0;
                (scannedImages instanceof Array) && i < scannedImages.length; i++) {
                var scannedImage = scannedImages[i];
                processOriginal(scannedImage);
            }

            var thumbnails = scanner.getScannedImages(response, false, true); // returns an array of ScannedImage
            for (var i = 0;
                (thumbnails instanceof Array) && i < thumbnails.length; i++) {
                var thumbnail = thumbnails[i];
                processThumbnail(thumbnail);
            }
        }

        /** Images scanned so far. */
        var imagesScanned = [];

        /** Processes an original */
        function processOriginal(scannedImage) {
            imagesScanned.push(scannedImage);
        }

        /** Processes a thumbnail */
        function processThumbnail(scannedImage) {
            var elementImg = scanner.createDomElementFromModel({
                'name': 'img',
                'attributes': {
                    'class': 'scanned border border-primary m-1',
                    'src': scannedImage.src
                }
            });
            document.getElementById('images').appendChild(elementImg);
        }

        /** Upload scanned images by submitting the form */
        function submitFormWithScannedImages() {
            if (scanner.submitFormWithImages('form1', imagesScanned, function(xhr) {
                    if (xhr.readyState == 4) { // 4: request finished and response is ready
                        document.getElementById('server_response').innerHTML =
                            "<b>Response from the server: </b><br>" + xhr.responseText;
                        $('#fileurl').val(xhr.responseText);
                        document.getElementById('images').innerHTML = ''; // clear images
                        imagesScanned = [];
                    }
                })) {
                document.getElementById('server_response').innerHTML = "Submitting, please stand by ...";
            } else {
                document.getElementById('server_response').innerHTML = "Form submission cancelled. Please scan first.";
            }
        }

        // cek pasien
        function cekPasien() {
            var norm = $('#norm').val();
            var url = "{{ route('api.caripasien') }}";
            $.LoadingOverlay("show");
            var formData = {
                norm: norm,
            };
            $.get(url, formData, function(data) {
                if (jQuery.isEmptyObject(data)) {
                    $.LoadingOverlay("hide");
                    swal.fire(
                        'Error',
                        "Pasien Nomor RM " + norm + " Tidak Ditemukan",
                        'error'
                    );
                } else {
                    console.log(data);
                    $('#nik').val(data.nik_bpjs);
                    $('#nomorkartu').val(data.no_Bpjs);
                    $('#nama').val(data.nama_px);
                    $('#tanggallahir').val(data.tgl_lahir);
                    $('#nohp').val(data.no_hp);
                    $.LoadingOverlay("hide");
                    swal.fire(
                        'Success',
                        "Pasien Nomor RM " + norm + " Ditemukan.",
                        'success'
                    );
                }
            }).fail(function(error) {
                swal.fire(
                    'Error',
                    "Nomor RM " + norm + " Tidak Ditemukan. Error : " + error,
                    'error'
                );
                $.LoadingOverlay("hide");
            });
        }

        function simpanDatabase() {
            var norm = $('#norm').val();
            var nomorkartu = $('#nomorkartu').val();
            var nik = $('#nik').val();
            var nama = $('#nama').val();
            var tanggallahir = $('#tanggallahir').val();
            var jenisberkas = $('#jenisberkas').find('option:selected').val();
            var namafile = $('#namafile').val();
            var tanggalscan = $('#tanggalscan').val();
            var fileurl = $('#fileurl').val();

            var url = "{{ route('efilerm.store') }}";
            $.LoadingOverlay("show");
            var formData = {
                norm: norm,
                nomorkartu: nomorkartu,
                nik: nik,
                nama: nama,
                tanggallahir: tanggallahir,
                jenisberkas: jenisberkas,
                namafile: namafile,
                tanggalscan: tanggalscan,
                fileurl: fileurl,
            };
            $.post(url, formData, function(data) {
                // console.log(data.metadata.code == 200);
                if (data.metadata.code == 200) {
                    $.LoadingOverlay("hide");
                    swal.fire(
                        'Success',
                        "Data Berhasil Disimpan dengan Nomor RM " + norm + ".",
                        'success'
                    );
                } else {
                    $.LoadingOverlay("hide");
                    swal.fire(
                        'Error',
                        data.metadata.message,
                        'error'
                    );
                }
            });
        }
    </script>
    {{-- csrf --}}
    <script type="text/javascript">
        $(document).ready(function() {
            $.ajaxSetup({
                headers: {
                    'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')
                }
            });
        });
    </script>

    <script>
        $(function() {
            $(document).on('click', '[data-toggle="lightbox"]', function(event) {
                event.preventDefault();
                $(this).ekkoLightbox({
                    alwaysShowClose: true
                });
            });
        })
    </script>
@endsection

@section('plugins.TempusDominusBs4', true)
