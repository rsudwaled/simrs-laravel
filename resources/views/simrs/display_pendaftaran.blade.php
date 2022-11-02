@extends('adminlte::page')


@if (empty($request->loket))
    @section('title', 'Display Antrian Pendaftaran')
    @section('content_header')
        <h1>Display Antrian Pendaftaran</h1>
    @stop
    @section('content')
        <div class="row">
            <div class="col-12">
                <x-adminlte-card title="Filter Data Display Antrian" theme="secondary" collapsible>
                    <form action="{{ route('antrian.display_pendaftaran') }}" method="get">
                        <div class="row">
                            <div class="col-md-3">
                                <x-adminlte-input name="user" label="User" readonly value="{{ Auth::user()->name }}" />
                            </div>
                            <div class="col-md-3">
                                @php
                                    $config = ['format' => 'YYYY-MM-DD'];
                                @endphp
                                <x-adminlte-input-date name="tanggal" label="Tanggal Antrian" :config="$config"
                                    value="{{ \Carbon\Carbon::parse($request->tanggal)->format('Y-m-d') }}">
                                    <x-slot name="prependSlot">
                                        <div class="input-group-text bg-primary">
                                            <i class="fas fa-calendar-alt"></i>
                                        </div>
                                    </x-slot>
                                </x-adminlte-input-date>
                            </div>
                            <div class="col-md-3">
                                <x-adminlte-select name="loket" label="Loket">
                                    <x-adminlte-options :options="[
                                        1 => 'Loket 1',
                                        2 => 'Loket 2',
                                        3 => 'Loket 3',
                                        4 => 'Loket 4',
                                        5 => 'Loket 5',
                                    ]" :selected="$request->loket ?? 1" />
                                </x-adminlte-select>
                            </div>
                            <div class="col-md-3">
                                <x-adminlte-select name="lantai" label="Lantai">
                                    <x-adminlte-options :options="[1 => 'Lantai 1', 2 => 'Lantai 2']" />
                                </x-adminlte-select>
                            </div>
                        </div>
                        <x-adminlte-button type="submit" class="withLoad" theme="primary" label="Submit Antrian" />
                    </form>
                </x-adminlte-card>
            </div>
        </div>
    @stop
@else
    @inject('layoutHelper', 'JeroenNoten\LaravelAdminLte\Helpers\LayoutHelper')
    @section('title', 'Display Pendaftaran')
    @section('body')
        <div class="wrapper p-3">
            <div class="row">
                <div class="col-md-6">
                    <x-adminlte-card title="Antrian Pendaftaran RSUD Waled" body-class="bg-gradient-gray-500"
                        theme="primary" icon="fas fa-qrcode">
                        <div class="text-center">
                            <h5><b> ANTRIAN DI PANGGIL</b></h5>
                            <h1 class="font-weight-bolder"><b>1</b></h1>

                        </div>
                    </x-adminlte-card>
                </div>
                <div class="col-md-6">
                    <x-adminlte-card theme="primary">
                        <iframe width="560" height="315" src="https://www.youtube.com/embed/oRj04KcUmuU?controls=0"
                            title="YouTube video player" frameborder="0"
                            allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                            allowfullscreen></iframe>
                        {{-- <div class="text-center">
                            <h6>Pilih Antrian Poliklinik</h6>
                            <div class="row">
                                @foreach ($poliklinik as $poli)
                                    <div class="col-md-3">
                                        <a class="withLoad"
                                            href="{{ route('antrian.tambah_offline', $poli->kodesubspesialis) }}">
                                            <x-adminlte-info-box
                                                text="{{ $poli->antrians->where('tanggalperiksa', \Carbon\Carbon::now()->format('Y-m-d'))->count() }}"
                                                title="POLI {{ $poli->namasubspesialis }}" theme="success" />
                                        </a>
                                    </div>
                                @endforeach
                            </div>
                        </div> --}}
                    </x-adminlte-card>
                </div>
            </div>
            <div class="row justify-content-md-center">
                <div class="col-md-2">
                    <div class="text-center">
                        <x-adminlte-small-box title="1" text="Loket 1" theme="success" />
                    </div>
                </div>
                <div class="col-md-2">
                    <div class="text-center">
                        <x-adminlte-small-box title="1" text="Loket 1" theme="success" />
                    </div>
                </div>
                <div class="col-md-2">
                    <div class="text-center">
                        <x-adminlte-small-box title="1" text="Loket 1" theme="success" />
                    </div>
                </div>
                <div class="col-md-2">
                    <div class="text-center">
                        <x-adminlte-small-box title="1" text="Loket 1" theme="success" />
                    </div>
                </div>
                <div class="col-md-2">
                    <div class="text-center">
                        <x-adminlte-small-box title="1" text="Loket 1" theme="success" />
                    </div>
                </div>
            </div>
        </div>
    @stop
    @section('adminlte_js')
        <script src="{{ asset('vendor/loading-overlay/loadingoverlay.min.js') }}"></script>
        <script src="{{ asset('vendor/onscan.js/onscan.min.js') }}"></script>
        {{-- scan --}}
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
        {{-- btn chekin --}}
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
        {{-- withLoad --}}
        <script>
            $(function() {
                $(".withLoad").click(function() {
                    $.LoadingOverlay("show");
                });
            })
        </script>
        @include('sweetalert::alert')
    @stop
@endif
