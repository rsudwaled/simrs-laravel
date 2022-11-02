@extends('adminlte::master')

@inject('layoutHelper', 'JeroenNoten\LaravelAdminLte\Helpers\LayoutHelper')

@section('title', 'Antrian QR Code')
@section('body')
    <div class="wrapper">
        <div class="row">
            <div class="col-12">
                <x-adminlte-card title="Aplikasi Checkin Antrian RSUD Waled" theme="primary" icon="fas fa-qrcode">
                </x-adminlte-card>
                <div class="text-center">
                    <br><br><br>
                    <h1>Silahkan lakukan scan QR Code Antrian online anda ...</h1>
                    <br>
                    {{-- With multiple slots and lg size --}}
                    <div class="row">
                        <div class="col-md-3">
                        </div>
                        <div class="col-md-6">
                            <x-adminlte-input name="kodebooking" label="Atau Masukan Kode Antrian (Checkin Manual)"
                                placeholder="Masukan Kode Antrian untuk Checkin" igroup-size="lg">
                                <x-slot name="appendSlot">
                                    <x-adminlte-button name="btn_checkin" id="btn_checkin" theme="success"
                                        label="Checkin!" />
                                </x-slot>
                                <x-slot name="prependSlot">
                                    <div class="input-group-text text-success">
                                        <i class="fas fa-qrcode"></i>
                                    </div>
                                </x-slot>
                            </x-adminlte-input>
                        </div>
                        <div class="col-md-3">
                        </div>
                    </div>
                    <i class="fas fa-qrcode fa-10x"></i>
                    <br><br>
                    <h2>Status = <span id="status">-</span></h2>
                </div>
            </div>
        </div>

        {{-- Footer --}}
        {{-- @include('adminlte::partials.footer.footer') --}}
    </div>
@stop

@section('adminlte_js')
    <script src="{{ asset('vendor/loading-overlay/loadingoverlay.min.js') }}"></script>
    <script src="{{ asset('vendor/onscan.js/onscan.min.js') }}"></script>
    <script>
        $(function() {
            onScan.attachTo(document, {
                onScan: function(sCode, iQty) {
                    $.LoadingOverlay("show", {
                        text: "Printing..."
                    });
                    var url = "{{ route('antrian.checkin_update') }}";
                    var formData = {
                        kodebooking: sCode,
                    };
                    $('#kodebooking').val(sCode);
                    $.get(url, formData, function(data) {
                        if (data.success == 'true') {
                            $('#status').html(data.metadata.message);
                        } else
                            $('#status').html(data.metadata.message);
                        $.LoadingOverlay("hide");
                    });
                    setTimeout(function() {
                        $.LoadingOverlay("show", {
                            text: "Reload..."
                        });
                        location.reload();
                        $('#status').html('-');

                    }, 2000);
                },
            });
        });
    </script>
    <script>
        $(function() {
            $('#btn_checkin').click(function() {
                var kodebooking = $('#kodebooking').val();
                $.LoadingOverlay("show", {
                    text: "Printing..."
                });
                var url = "{{ route('antrian.checkin_update') }}";
                var formData = {
                    kodebooking: kodebooking,
                };
                $('#kodebooking').val(kodebooking);
                $.get(url, formData, function(data) {
                    if (data.success == 'true') {
                        $('#status').html(data.metadata.message);
                    } else
                        $('#status').html(data.metadata.message);
                    $.LoadingOverlay("hide");
                    setTimeout(function() {
                        $.LoadingOverlay("show", {
                            text: "Reload..."
                        });
                        location.reload();
                        $('#status').html('-');
                    }, 3000);
                });
            });
        });
    </script>
    @include('sweetalert::alert')
@stop
