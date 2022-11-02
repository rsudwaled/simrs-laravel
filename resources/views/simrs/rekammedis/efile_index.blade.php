@extends('adminlte::page')

@section('title', 'Scan E-File Rekam Medis')

@section('content_header')
    <h1>Scan E-File Rekam Medis</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-12">
            <x-adminlte-card title="Data E-File Rekam Medis" theme="warning" collapsible>
                <a class="btn btn-success mb-1" href="{{ route('efilerm.create') }}">Scan E-File RM</a>
                @php
                    $heads = ['No.', 'No RM', ' Nama', 'Tgl Lahir', 'Nama Berkas', 'Tgl Scan', 'Jenis', 'Action'];
                    $config = [
                        'buttons' => [
                            [
                                'extend' => 'colvis',
                                'className' => 'btn-info',
                            ],
                            [
                                'extend' => 'print',
                                'className' => 'btn-info',
                            ],
                            [
                                'extend' => 'pdf',
                                'className' => 'btn-info',
                            ],
                        ],
                    ];
                @endphp
                <x-adminlte-datatable id="table1" class="nowrap" :heads="$heads" :config="$config" striped bordered
                    hoverable compressed with-buttons>
                    @foreach ($filerm as $item)
                        <tr>
                            <td>{{ $item->id }}</td>
                            <td>{{ $item->norm }}</td>
                            <td>{{ $item->nama }}</td>
                            <td>{{ \Carbon\Carbon::parse($item->tanggallahir)->format('Y-m-d') }}</td>
                            <td>{{ $item->namafile }}</td>
                            <td>{{ $item->tanggalscan }}</td>
                            <td>
                                @if ($item->jenisberkas == 1)
                                    Rawat Inap
                                @endif
                                @if ($item->jenisberkas == 2)
                                    Rawat Jalan
                                @endif
                                @if ($item->jenisberkas == 3)
                                    Penunjang
                                @endif
                                @if ($item->jenisberkas == 4)
                                    Berkas Pasien
                                @endif
                            </td>
                            <td>
                                <a href="{{ $item->fileurl }}" target="_blank" class="btn btn-primary btn-xs"><i
                                        class=" fas fa-download"></i></a>
                                <x-adminlte-button icon="fas fa-eye" theme="warning" class="btn-xs btnLihat" label="Lihat"
                                    data-id="{{ $item->id }}" />
                            </td>
                        </tr>
                    @endforeach
                </x-adminlte-datatable>
            </x-adminlte-card>
        </div>
    </div>
    <x-adminlte-modal id="modalFile" size="lg" theme="warning" title="E-File Rekam Medis">
        <div class="row">
            <div class="col-md-6">
                <div class="row">
                    <dt class="col-sm-4">Pasien</dt>
                    <dd class="col-sm-8">: <span id="nama"></span> / <span id="norm"></span></dd>
                    <dt class="col-sm-4">BPJS / NIK</dt>
                    <dd class="col-sm-8">: <span id="nomorkartu"></span> / <span id="nik"></span></dd>
                </div>
            </div>
            <div class="col-md-6">
                <div class="row">
                    <dt class="col-sm-4">Nama Berkas</dt>
                    <dd class="col-sm-8">:
                        <span id="namafile"></span> /
                        <span id="jenisberkas"></span>
                    </dd>
                    <dt class="col-sm-4">Tanggal Scan</dt>
                    <dd class="col-sm-8">: <span id="tanggalscan"></span></dd>
                </div>
            </div>
        </div>
        <iframe id="fileurl" src="" width="100%" height="500px">
        </iframe>
    </x-adminlte-modal>
@stop

@section('plugins.Datatables', true)
@section('plugins.DatatablesPlugins', true)
@section('plugins.TempusDominusBs4', true)
@section('plugins.Select2', true)

@section('js')
    <script>
        $(function() {
            $.ajaxSetup({
                headers: {
                    'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')
                }
            });
            $('.btnLihat').click(function() {
                var id = $(this).data('id');
                $.LoadingOverlay("show");
                var url = "{{ route('efilerm.index') }}" + '/' + id;
                $.get(url, function(data) {
                    $('#norm').html(data.norm);
                    $('#nama').html(data.nama);
                    $('#nik').html(data.nik);
                    $('#nomorkartu').html(data.nomorkartu);
                    $('#nomorantrean').html(data.nomorantrean);
                    $('#namafile').html(data.namafile);
                    $('#jenisberkas').html(data.jenisberkas);
                    $('#jenisberkas').html(data.jenisberkas);
                    $('#tanggalscan').html(data.tanggalscan);
                    $("#fileurl").attr("src", data.fileurl);
                    $('#modalFile').modal('show');
                    $.LoadingOverlay("hide", true);
                })
            });
        });
    </script>
@endsection
